package resolver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	handshakeTimeout = 5 * time.Second
	idleTimeout      = 30 * time.Second
	maxDNSMessage    = 65535

	// shutdownGrace is how long in-flight work has to finish before listeners
	// are closed forcibly.
	shutdownGrace = 10 * time.Second
)

// Listeners wires the transports to the resolver. Each transport differs only
// in how it establishes the tenant identity.
type Listeners struct {
	cfg     Config
	res     *Resolver
	st      Store
	tls     *tls.Config
	limiter *RateLimiter
	log     *slog.Logger

	mu      sync.Mutex
	closers []func() error
	closed  bool
}

func NewListeners(cfg Config, res *Resolver, st Store, tlsCfg *tls.Config) *Listeners {
	return &Listeners{cfg: cfg, res: res, st: st, tls: tlsCfg, log: slog.Default()}
}

func (l *Listeners) WithRateLimiter(r *RateLimiter) *Listeners { l.limiter = r; return l }

func (l *Listeners) WithLogger(lg *slog.Logger) *Listeners {
	if lg != nil {
		l.log = lg
	}
	return l
}

// track registers a shutdown function, or runs it immediately if shutdown has
// already begun — which is what prevents a listener started during shutdown
// from being left running.
func (l *Listeners) track(fn func() error) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		go fn()
		return false
	}
	l.closers = append(l.closers, fn)
	return true
}

// Shutdown closes every listener. In-flight queries finish because each
// connection has its own deadline; new connections are refused immediately.
func (l *Listeners) Shutdown() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	closers := l.closers
	l.closers = nil
	l.mu.Unlock()

	for _, fn := range closers {
		if err := fn(); err != nil {
			l.log.Debug("listener close", "err", err)
		}
	}
}

// ---- DNS over TLS ----

// ServeDoT accepts TLS connections and reads the tenant from the SNI in the
// ClientHello. This is the whole per-customer identification mechanism: the
// customer sets Private DNS to "<routeID>.<base_domain>", and the routeID
// arrives in the handshake before a single query is sent.
func (l *Listeners) ServeDoT(addr string) error {
	ln, err := tls.Listen("tcp", addr, l.tls)
	if err != nil {
		return err
	}
	l.log.Info("listening", "transport", "dot", "addr", addr, "base_domain", l.cfg.BaseDomain)
	return l.ServeDoTListener(ln)
}

// ServeDoTListener serves DoT on an already-established TLS listener.
func (l *Listeners) ServeDoTListener(ln net.Listener) error {
	if !l.track(ln.Close) {
		return nil
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return nil // expected during shutdown
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		go l.handleDoT(conn)
	}
}

func (l *Listeners) handleDoT(conn net.Conn) {
	defer conn.Close()

	tc, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	tc.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tc.Handshake(); err != nil {
		return
	}

	sni := tc.ConnectionState().ServerName
	routeID := routeIDFromSNI(sni, l.cfg.BaseDomain)
	if routeID == "" {
		// Connected to the bare hostname with no tenant label. Nothing to
		// serve — close rather than answering as an open resolver.
		return
	}

	// Cap concurrent connections per tenant so a single shared hostname cannot
	// exhaust the process's file descriptors.
	release, ok := l.limiter.AcquireConn(routeID)
	if !ok {
		return
	}
	defer release()

	src, _, _ := net.SplitHostPort(tc.RemoteAddr().String())
	l.serveStream(tc, identity{routeID: routeID, via: "sni", srcIP: src})
}

// serveStream handles length-prefixed DNS messages, the framing used by both
// DNS-over-TCP and DNS-over-TLS.
func (l *Listeners) serveStream(conn net.Conn, id identity) {
	var lenBuf [2]byte
	for {
		conn.SetDeadline(time.Now().Add(idleTimeout))

		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(lenBuf[:])
		if n == 0 {
			return
		}

		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf); err != nil {
			// A message we cannot parse is not something to answer; the framing
			// is no longer trustworthy, so drop the connection.
			l.res.m.Malformed.Add(1)
			return
		}

		reply := l.res.Resolve(req, id)
		out, err := reply.Pack()
		if err != nil || len(out) > maxDNSMessage {
			return
		}

		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(out)))
		if _, err := conn.Write(append(lenBuf[:], out...)); err != nil {
			return
		}
	}
}

// ---- plain DNS on :53 ----

// ServePlain serves unencrypted DNS, where the only available identity is the
// source address. Needed because iOS profiles, routers and older Android
// cannot all speak DoT.
func (l *Listeners) ServePlain(addr string) error {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		host, _, err := net.SplitHostPort(w.RemoteAddr().String())
		if err != nil {
			return
		}

		reply := l.res.Resolve(req, identity{ip: host, via: "ip", srcIP: host})

		// Truncate to what this client said it can accept, so an oversized
		// answer triggers a TCP retry instead of being silently dropped by a
		// middlebox.
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
			reply.Truncate(int(clientUDPSize(req)))
		}
		_ = w.WriteMsg(reply)
	})

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: handler, UDPSize: maxUDPSize}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	if !l.track(func() error {
		udp.Shutdown()
		return tcp.Shutdown()
	}) {
		return nil
	}

	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()
	l.log.Info("listening", "transport", "plain", "addr", addr, "auth", "source-ip")

	return <-errCh
}

// ---- DNS over HTTPS ----

// ServeDoH serves RFC 8484 DoH. The tenant comes from the SNI exactly as it
// does for DoT, so one wildcard certificate covers both transports.
func (l *Listeners) ServeDoH(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", l.dohHandler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         l.tls,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	if !l.track(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return srv.Shutdown(ctx)
	}) {
		return nil
	}

	l.log.Info("listening", "transport", "doh", "addr", addr, "path", "/dns-query")
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (l *Listeners) dohHandler(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		raw, err = base64.RawURLEncoding.DecodeString(q)
	case http.MethodPost:
		raw, err = io.ReadAll(io.LimitReader(r.Body, maxDNSMessage))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(raw) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		l.res.m.Malformed.Add(1)
		http.Error(w, "malformed dns message", http.StatusBadRequest)
		return
	}

	routeID := ""
	if r.TLS != nil {
		routeID = routeIDFromSNI(r.TLS.ServerName, l.cfg.BaseDomain)
	}
	if routeID == "" {
		http.Error(w, "unknown resolver hostname", http.StatusForbidden)
		return
	}

	src, _, _ := net.SplitHostPort(r.RemoteAddr)
	reply := l.res.Resolve(req, identity{routeID: routeID, via: "sni", srcIP: src})
	out, err := reply.Pack()
	if err != nil {
		http.Error(w, "pack failure", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(out)
}
