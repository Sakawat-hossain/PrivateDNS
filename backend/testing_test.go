package backend

import (
	"io"
	"log/slog"
)

// discardLogger keeps test output readable. Handler errors are asserted on
// through status codes, not log scraping.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
