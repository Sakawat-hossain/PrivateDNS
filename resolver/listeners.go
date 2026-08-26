package resolver

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const (
	handshakeTimeout = 5 * time.Second
	idleTimeout      = 30 * time.Second
	maxDNSMessage    = 65535
)

// Listeners wires the transports to the resolver. Each transport differs only
// in how it establishes the tenant identity.
type Listeners struct {
	cfg Config
	res *Resolver
	st  *Store
	tls *tls.Config
}

func NewListeners(cfg Config, res *Resolver, st *Store, tlsCfg *tls.Config) *Listeners {
	return &Listeners{cfg: cfg, res: res, st: st, tls: tlsCfg}
}

// ---- DNS over TLS ----

// ServeDoT accepts TLS connections and reads the tenant from the SNI in the
// ClientHello. This is the whole per-customer identification mechanism: the
// customer sets Private DNS to "<routeID>.dns.example.com", and the routeID
// arrives in the handshake before a single query is sent.
func (l *Listeners) ServeDoT(addr string) error {
	ln, err := tls.Listen("tcp", addr, l.tls)
	if err != nil {
		return err
	}
	log.Printf("DoT listening on %s (base domain %s)", addr, l.cfg.BaseDomain)
	return l.ServeDoTListener(ln)
}

// ServeDoTListener serves DoT on an already-established TLS listener.
func (l *Listeners) ServeDoTListener(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
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

	l.serveStream(tc, identity{routeID: routeID, via: "sni"})
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

		reply := l.res.Resolve(req, identity{ip: host, via: "ip"})
		_ = w.WriteMsg(reply)
	})

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: handler, UDPSize: 4096}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()
	log.Printf("plain DNS listening on %s (udp+tcp, source-IP auth)", addr)

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
	}
	log.Printf("DoH listening on %s/dns-query", addr)
	return srv.ListenAndServeTLS("", "")
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

	reply := l.res.Resolve(req, identity{routeID: routeID, via: "sni"})
	out, err := reply.Pack()
	if err != nil {
		http.Error(w, "pack failure", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}
