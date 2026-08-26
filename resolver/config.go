package resolver

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config is the on-disk configuration, loaded from a JSON file.
type Config struct {
	// BaseDomain is the suffix that per-tenant hostnames hang off.
	// A client connecting to "a1b2c3.dns.example.com" with BaseDomain
	// "dns.example.com" is identified as tenant "a1b2c3".
	BaseDomain string `json:"base_domain"`

	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`

	ListenDoT   string `json:"listen_dot"`   // ":853", empty to disable
	ListenDoH   string `json:"listen_doh"`   // ":443", empty to disable
	ListenPlain string `json:"listen_plain"` // ":53",  empty to disable
	ListenAdmin string `json:"listen_admin"` // "127.0.0.1:8053", metrics + provisioning

	// Upstreams are the recursive resolvers queries are forwarded to.
	// In production these point at a local Unbound; 1.1.1.1 works for testing.
	Upstreams []string `json:"upstreams"`

	DBPath       string   `json:"db_path"`
	BlocklistDir string   `json:"blocklist_dir"`
	AdminTokens  []string `json:"admin_tokens"`

	// OpenPlain allows unauthenticated queries on the plain :53 listener.
	// Leave false. An open resolver is a DNS amplification vector.
	OpenPlain bool `json:"open_plain"`
}

func DefaultConfig() Config {
	return Config{
		BaseDomain:   "dns.example.com",
		CertFile:     "/etc/private-dns/certs/fullchain.pem",
		KeyFile:      "/etc/private-dns/certs/privkey.pem",
		ListenDoT:    ":853",
		ListenDoH:    ":443",
		ListenPlain:  ":53",
		ListenAdmin:  "127.0.0.1:8053",
		Upstreams:    []string{"1.1.1.1:53", "1.0.0.1:53"},
		DBPath:       "/var/lib/private-dns/policy.db",
		BlocklistDir: "/var/lib/private-dns/blocklists",
		OpenPlain:    false,
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}

	cfg.BaseDomain = strings.ToLower(strings.Trim(cfg.BaseDomain, "."))
	if cfg.BaseDomain == "" {
		return cfg, fmt.Errorf("base_domain is required")
	}
	if len(cfg.Upstreams) == 0 {
		return cfg, fmt.Errorf("at least one upstream is required")
	}
	return cfg, nil
}

// WriteSample writes a starter config so a fresh install has something to edit.
func WriteSample(path string) error {
	cfg := DefaultConfig()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
