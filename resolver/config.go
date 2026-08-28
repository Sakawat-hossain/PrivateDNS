package resolver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// envPrefix namespaces the environment overrides. Every configuration key can
// be set as PRIVATEDNS_<KEY>, which is what container deployments need — the
// file supplies defaults and the environment adjusts them per instance.
const envPrefix = "PRIVATEDNS_"

// Config is the resolver's configuration. Every environment-specific value
// lives here rather than in source: no domain, address, path or credential is
// compiled into the binary.
type Config struct {
	// BaseDomain is the suffix that per-tenant hostnames hang off. A client
	// connecting to "a1b2c3.dns.example.com" with BaseDomain "dns.example.com"
	// is identified as tenant "a1b2c3".
	BaseDomain string `yaml:"base_domain" json:"base_domain"`

	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`

	ListenDoT   string `yaml:"listen_dot" json:"listen_dot"`     // ":853", empty disables
	ListenDoH   string `yaml:"listen_doh" json:"listen_doh"`     // ":443", empty disables
	ListenPlain string `yaml:"listen_plain" json:"listen_plain"` // ":53",  empty disables
	ListenAdmin string `yaml:"listen_admin" json:"listen_admin"` // metrics + provisioning

	// Upstreams are the recursive resolvers queries are forwarded to. Point
	// these at a local Unbound in production; a public resolver works for
	// testing but sees every query your customers make.
	Upstreams []string `yaml:"upstreams" json:"upstreams"`

	DBPath       string   `yaml:"db_path" json:"db_path"`
	BlocklistDir string   `yaml:"blocklist_dir" json:"blocklist_dir"`
	AdminTokens  []string `yaml:"admin_tokens" json:"admin_tokens"`

	// OpenPlain allows unauthenticated queries on the plain :53 listener.
	// Leave false. An open resolver is a DNS amplification vector and will
	// get the host onto abuse lists.
	// BindClientIP records the address each tenant queries from, so the SNI
	// proxy recognises the same customer when their app connects to it.
	//
	// Without it every customer address must be registered by hand and
	// re-registered whenever their network changes it -- several times a day
	// on mobile. The DNS query is the one moment both the tenant and their
	// address are visible together.
	//
	// Only meaningful with a proxy tier. Off by default: it writes customer
	// addresses to the database, which a deployment without a proxy has no
	// reason to store.
	BindClientIP bool `yaml:"bind_client_ip" json:"bind_client_ip"`

	OpenPlain bool `yaml:"open_plain" json:"open_plain"`

	// RateLimitQPS caps sustained queries per second for a single tenant.
	// Zero disables rate limiting entirely.
	RateLimitQPS float64 `yaml:"rate_limit_qps" json:"rate_limit_qps"`

	// RateLimitBurst is how far above the sustained rate a tenant may spike.
	// Page loads arrive in bursts, so this needs headroom or normal browsing
	// gets throttled.
	RateLimitBurst int `yaml:"rate_limit_burst" json:"rate_limit_burst"`

	// MaxConnsPerTenant bounds concurrent DoT connections from one tenant.
	// Zero means unlimited.
	MaxConnsPerTenant int `yaml:"max_conns_per_tenant" json:"max_conns_per_tenant"`

	// StripECS removes EDNS Client Subnet from forwarded queries so upstream
	// resolvers cannot learn which subnet a customer is on. On by default:
	// privacy is the product.
	StripECS bool `yaml:"strip_ecs" json:"strip_ecs"`

	// BlockRebind strips private-space addresses from upstream answers.
	//
	// On by default. A public name resolving to 192.168.x has no legitimate
	// use and is how a browser gets turned into a proxy into the network it
	// sits on.
	BlockRebind bool `yaml:"block_rebind" json:"block_rebind"`

	// RebindAllowDomains are names permitted to resolve into private space.
	//
	// Split-horizon DNS is a real arrangement -- an internal name resolving to
	// 10.x is correct on a corporate network -- so it needs an exemption rather
	// than forcing the protection off entirely.
	RebindAllowDomains []string `yaml:"rebind_allow_domains" json:"rebind_allow_domains"`

	// LogLevel is one of debug, info, warn, error.
	LogLevel string `yaml:"log_level" json:"log_level"`

	// LogFormat is "text" or "json". JSON suits log shipping; text is
	// readable in a terminal.
	LogFormat string `yaml:"log_format" json:"log_format"`
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
		Upstreams:    []string{"127.0.0.1:5335"},
		DBPath:       "/var/lib/private-dns/policy.db",
		BlocklistDir: "/var/lib/private-dns/blocklists",
		OpenPlain:    false,

		// A household generates a few queries per second while browsing and
		// spikes hard on page load. 50/s sustained with a burst of 200 leaves
		// normal use untouched while stopping a leaked hostname being used to
		// flood the resolver.
		RateLimitQPS:      50,
		RateLimitBurst:    200,
		MaxConnsPerTenant: 64,

		StripECS:    true,
		BlockRebind: true,
		LogLevel:    "info",
		LogFormat:   "text",
	}
}

// LoadConfig reads configuration from path, then applies environment
// overrides. The format is chosen by file extension: .yaml/.yml parse as YAML,
// anything else as JSON.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("parse yaml config: %w", err)
		}
	default:
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("parse json config: %w", err)
		}
	}

	applyEnvOverrides(&cfg)

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate normalises the configuration and rejects combinations that cannot
// work, so a mistake surfaces at startup rather than as a puzzling runtime
// failure hours later.
func (c *Config) Validate() error {
	c.BaseDomain = normalizeDomain(c.BaseDomain)
	if c.BaseDomain == "" {
		return fmt.Errorf("base_domain is required")
	}
	if strings.Count(c.BaseDomain, ".") < 1 {
		return fmt.Errorf("base_domain %q must be a fully-qualified name", c.BaseDomain)
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	for i, u := range c.Upstreams {
		if !strings.Contains(u, ":") {
			// A bare address silently fails to dial; default the DNS port
			// rather than making the operator discover this the hard way.
			c.Upstreams[i] = u + ":53"
		}
	}
	if (c.ListenDoT != "" || c.ListenDoH != "") && (c.CertFile == "" || c.KeyFile == "") {
		return fmt.Errorf("cert_file and key_file are required when DoT or DoH is enabled")
	}
	if c.ListenDoT == "" && c.ListenDoH == "" && c.ListenPlain == "" {
		return fmt.Errorf("no listener is enabled")
	}
	switch strings.ToLower(c.LogLevel) {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q must be debug, info, warn or error", c.LogLevel)
	}
	if c.RateLimitQPS > 0 && c.RateLimitBurst <= 0 {
		// A burst of zero would reject every query, which looks like a total
		// outage rather than a misconfiguration.
		return fmt.Errorf("rate_limit_burst must be positive when rate_limit_qps is set")
	}
	return nil
}

// applyEnvOverrides maps PRIVATEDNS_<KEY> onto the matching field, using the
// yaml tag as the key. Slice fields accept a comma-separated list.
//
// Environment beats file so that a container image can ship a baseline config
// and be adjusted per deployment without rebuilding it.
func applyEnvOverrides(cfg *Config) {
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}

		raw, ok := os.LookupEnv(envPrefix + strings.ToUpper(tag))
		if !ok {
			continue
		}
		raw = strings.TrimSpace(raw)

		field := v.Field(i)
		switch field.Kind() {
		case reflect.String:
			field.SetString(raw)
		case reflect.Bool:
			if b, err := strconv.ParseBool(raw); err == nil {
				field.SetBool(b)
			}
		case reflect.Int:
			if n, err := strconv.Atoi(raw); err == nil {
				field.SetInt(int64(n))
			}
		case reflect.Float64:
			if f, err := strconv.ParseFloat(raw, 64); err == nil {
				field.SetFloat(f)
			}
		case reflect.Slice:
			if field.Type().Elem().Kind() != reflect.String {
				continue
			}
			if raw == "" {
				field.Set(reflect.ValueOf([]string{}))
				continue
			}
			parts := strings.Split(raw, ",")
			for j := range parts {
				parts[j] = strings.TrimSpace(parts[j])
			}
			field.Set(reflect.ValueOf(parts))
		}
	}
}

// WriteSample writes a starter configuration so a fresh install has something
// to edit. The format follows the file extension.
func WriteSample(path string) error {
	cfg := DefaultConfig()
	cfg.AdminTokens = []string{"GENERATE_WITH_openssl_rand_hex_32"}

	var (
		out []byte
		err error
	)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		out, err = yaml.Marshal(cfg)
	default:
		out, err = json.MarshalIndent(cfg, "", "  ")
		out = append(out, '\n')
	}
	if err != nil {
		return err
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// 0600: the file carries admin tokens.
	return os.WriteFile(path, out, 0o600)
}
