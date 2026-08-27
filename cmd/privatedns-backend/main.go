// Command privatedns-backend serves the administration and provisioning API.
//
// It shares the resolver's database rather than keeping its own, so there is
// one source of truth about who has paid and a revocation takes effect on both
// tiers at once.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
	"gopkg.in/yaml.v3"
)

var version = "dev"

func main() {
	var (
		configPath  = flag.String("config", "/etc/private-dns/backend.yaml", "path to the configuration file")
		showVersion = flag.Bool("version", false, "print the version and exit")
		createAdmin = flag.String("create-admin", "", "create an administrator with this email, then exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	backend.Version = version

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	srv, err := backend.New(cfg, logger)
	if err != nil {
		logger.Error("start", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	if *createAdmin != "" {
		if err := bootstrapAdmin(srv, *createAdmin); err != nil {
			logger.Error("create admin", "err", err)
			os.Exit(1)
		}
		return
	}

	// A backend with no accounts cannot be signed into, and there is no
	// self-registration by design. Say so rather than leaving the operator to
	// discover it at a login form.
	if n, err := srv.Store().CountUsers(); err == nil && n == 0 {
		logger.Warn("no accounts exist; create one with -create-admin <email>")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}

// bootstrapAdmin creates the first administrator.
//
// The password is read from PRIVATEDNS_ADMIN_PASSWORD rather than a flag,
// because command-line arguments are visible to every process on the host
// through the process table.
func bootstrapAdmin(srv *backend.Server, email string) error {
	password := os.Getenv("PRIVATEDNS_ADMIN_PASSWORD")
	if password == "" {
		return fmt.Errorf("set PRIVATEDNS_ADMIN_PASSWORD; it is not accepted as a flag " +
			"because arguments are visible in the process table")
	}

	user, err := srv.Store().CreateUser(email, "Administrator", password, backend.RoleAdmin)
	if err != nil {
		return err
	}

	fmt.Printf("created administrator %s (id %d)\n", user.Email, user.ID)
	return nil
}

func loadConfig(path string) (backend.Config, error) {
	cfg := backend.DefaultConfig()

	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("parse yaml: %w", err)
		}
	default:
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("parse json: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func newLogger(cfg backend.Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(cfg.LogFormat, "json") {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
