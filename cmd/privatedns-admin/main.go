// Command privatedns-admin serves the operator dashboard.
//
// It binds to loopback by default and warns loudly if it does not. This surface
// issues and revokes tenants, edits routing, and reads an audit log that spans
// every reseller — it is an operator tool, not a public one.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Sakawat-hossain/PrivateDNS/admin"
	"gopkg.in/yaml.v3"
)

var version = "dev"

func main() {
	var (
		configPath  = flag.String("config", "/etc/private-dns/admin.yaml", "path to the configuration file")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	admin.Version = version

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	srv, err := admin.New(cfg, logger)
	if err != nil {
		logger.Error("start", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}

func loadConfig(path string) (admin.Config, error) {
	cfg := admin.DefaultConfig()

	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func newLogger(cfg admin.Config) *slog.Logger {
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
