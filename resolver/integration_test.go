package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testBase = "dns.test"

// selfSignedWildcard mints the same shape of certificate the real service
// needs: one wildcard covering every per-tenant hostname under the base.
func selfSignedWildcard(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testBase},
		DNSNames:              []string{testBase, "*." + testBase},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeUpstream is a real DNS server answering every A query with a fixed
// address, standing in for Unbound.
func fakeUpstream(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name: req.Question[0].Name, Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: 300,
					},
					A: net.ParseIP("198.51.100.1"),
				})
			}
			w.WriteMsg(m)
		}),
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	return pc.LocalAddr().String()
}

// startDoT wires a full server stack onto an ephemeral port and returns its
// address plus the policy store, so tests can provision tenants.
func startDoT(t *testing.T) (string, *Store) {
	t.Helper()

	store, err := OpenStore(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("ads.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	block := NewBlocklist(dir)
	if _, err := block.Load(); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.BaseDomain = testBase
	cfg.Upstreams = []string{fakeUpstream(t)}

	res := NewResolver(cfg, store, block, NewCache(), &Metrics{})

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedWildcard(t)}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go NewListeners(cfg, res, store, tlsCfg).ServeDoTListener(ln)

	return ln.Addr().String(), store
}

// dotQuery performs a genuine DoT exchange: TLS handshake carrying the tenant
// in the SNI, then a length-prefixed DNS message.
func dotQuery(t *testing.T, addr, sni, name string, qtype uint16) (*dns.Msg, error) {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // self-signed test certificate
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	packed, err := req.Pack()
	if err != nil {
		return nil, err
	}

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(packed)))
	if _, err := conn.Write(append(prefix[:], packed...)); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(buf); err != nil {
		return nil, err
	}
	return reply, nil
}

func TestDoTEndToEnd(t *testing.T) {
	addr, store := startDoT(t)

	if err := store.CreateTenant("tenant01", "integration", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	store.SetOverride("*", "bkash.com", "203.0.113.10")
	store.Reload()

	sni := "tenant01." + testBase

	t.Run("resolves a normal name upstream", func(t *testing.T) {
		reply, err := dotQuery(t, addr, sni, "example.com", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[reply.Rcode])
		}
		if len(reply.Answer) != 1 {
			t.Fatalf("got %d answers, want 1", len(reply.Answer))
		}
		if a := reply.Answer[0].(*dns.A); a.A.String() != "198.51.100.1" {
			t.Fatalf("answer = %s, want 198.51.100.1", a.A)
		}
	})

	t.Run("blocks a filtered name", func(t *testing.T) {
		reply, err := dotQuery(t, addr, sni, "ads.example", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[reply.Rcode])
		}
	})

	t.Run("routes an overridden name to the proxy", func(t *testing.T) {
		reply, err := dotQuery(t, addr, sni, "api.bkash.com", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		if len(reply.Answer) != 1 {
			t.Fatalf("got %d answers, want 1", len(reply.Answer))
		}
		if a := reply.Answer[0].(*dns.A); a.A.String() != "203.0.113.10" {
			t.Fatalf("answer = %s, want the proxy address", a.A)
		}
	})

	t.Run("refuses an unknown tenant", func(t *testing.T) {
		reply, err := dotQuery(t, addr, "nosuchtenant."+testBase, "example.com", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Rcode != dns.RcodeRefused {
			t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[reply.Rcode])
		}
	})

	t.Run("closes a connection to the bare hostname", func(t *testing.T) {
		// No tenant label means nothing to serve. The connection must be
		// dropped rather than answered, or we are an open resolver.
		if _, err := dotQuery(t, addr, testBase, "example.com", dns.TypeA); err == nil {
			t.Fatal("expected the bare hostname to be refused a connection")
		}
	})
}

func TestDoTRevocationClosesAccess(t *testing.T) {
	addr, store := startDoT(t)
	store.CreateTenant("tenant02", "", time.Now().Add(time.Hour).Unix())
	store.Reload()

	sni := "tenant02." + testBase

	reply, err := dotQuery(t, addr, sni, "example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("setup: rcode = %s", dns.RcodeToString[reply.Rcode])
	}

	store.SetStatus("tenant02", "suspended")
	store.Reload()

	reply, err = dotQuery(t, addr, sni, "example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED after revocation", dns.RcodeToString[reply.Rcode])
	}
}
