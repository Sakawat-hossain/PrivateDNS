package resolver

import (
	"crypto/tls"
	"fmt"
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

	if _, err := load(); err != nil {
		return nil, fmt.Errorf("load %s / %s: %w", cfg.CertFile, cfg.KeyFile, err)
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", "dot"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return load()
		},
	}, nil
}
