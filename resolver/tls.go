package resolver

import (
	"crypto/tls"
	"sync"
	"time"
)

// certReloadInterval bounds how long a renewed certificate takes to come into
// service. Handshakes are frequent, so re-reading on every one would be
// wasteful; a minute is short enough that a renewal is never noticed.
const certReloadInterval = time.Minute

// LoadTLS builds the TLS configuration shared by the DoT and DoH listeners.
//
// The certificate must cover *.<base_domain>, because every tenant connects to
// its own hostname beneath that base. A wildcard can only be issued over the
// ACME DNS-01 challenge — HTTP-01 cannot produce one.
//
// Certificates are re-read from disk rather than pinned at startup, so a
// renewal takes effect without restarting the service or dropping connections.
//
// A missing certificate is NOT an error here. On a fresh install there is no
// certificate until the operator has pointed DNS at the host and run the ACME
// client, and refusing to start until then took the whole service down --
// including the admin endpoint needed to check on it, and the plain listener.
// The process would exit, systemd would restart it, and the log filled with
// hundreds of identical failures while the operator worked through the setup
// steps. Instead the listeners come up and handshakes fail until a certificate
// appears, at which point they start succeeding on their own within
// certReloadInterval. HaveCert reports which state you are in.
func LoadTLS(cfg Config) (*tls.Config, error) {
	var (
		mu     sync.RWMutex
		cached *tls.Certificate
		loaded time.Time
	)

	load := func() (*tls.Certificate, error) {
		mu.RLock()
		if cached != nil && time.Since(loaded) < certReloadInterval {
			defer mu.RUnlock()
			return cached, nil
		}
		mu.RUnlock()

		crt, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			// A renewal that is mid-write leaves the pair briefly inconsistent.
			// Keep serving the previous certificate rather than failing
			// handshakes for the seconds it takes to settle.
			mu.RLock()
			defer mu.RUnlock()
			if cached != nil {
				return cached, nil
			}
			return nil, err
		}

		mu.Lock()
		cached, loaded = &crt, time.Now()
		mu.Unlock()
		return &crt, nil
	}

	// Probe once so a genuinely broken pair is visible in the log at startup
	// rather than only when the first client connects. Not fatal: see above.
	_, _ = load()
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", "dot"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return load()
		},
	}, nil
}

// HaveCert reports whether a usable certificate and key are on disk right now.
//
// Used to decide what to log at startup and what readiness should say, so the
// difference between "waiting for a certificate" and "serving" is visible
// without reading a handshake failure.
func HaveCert(cfg Config) bool {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return false
	}
	_, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	return err == nil
}
