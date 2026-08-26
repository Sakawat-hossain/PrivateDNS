package resolver

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger builds the structured logger from configuration.
//
// Text is the default because an operator reading journalctl wants readable
// lines; JSON suits a log shipper. Either way the resolver logs events and
// aggregate counts, never the domains a customer looked up.
func NewLogger(cfg Config) *slog.Logger {
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

	var handler slog.Handler
	if strings.EqualFold(cfg.LogFormat, "json") {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}

// redactName is used where a domain would otherwise be written to a log.
//
// Query names are deliberately not logged. At debug level the resolver reports
// the parent domain only, which is enough to investigate a filtering
// complaint without recording browsing history.
func redactName(name string) string {
	parts := domainSuffixes(name)
	if len(parts) < 2 {
		return "(redacted)"
	}
	// parts[len-1] is the TLD; the one before it is the registrable-ish parent.
	return parts[len(parts)-2]
}
