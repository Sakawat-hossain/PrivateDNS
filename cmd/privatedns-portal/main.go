// Command privatedns-portal serves the customer-facing web interface.
//
// It is a separate binary from the backend API on purpose. The portal is meant
// to face the public internet; the administration API is not, and running them
// in one process would force a single exposure decision on both.
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

	"github.com/Sakawat-hossain/PrivateDNS/portal"
	"gopkg.in/yaml.v3"
)

var version = "dev"

func main() {
	var (
		configPath  = flag.String("config", "/etc/private-dns/portal.yaml", "path to the configuration file")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	portal.Version = version

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	srv, err := portal.New(cfg, logger)
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

func loadConfig(path string) (portal.Config, error) {
	cfg := portal.DefaultConfig()

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

func newLogger(cfg portal.Config) *slog.Logger {
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
