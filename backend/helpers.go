package backend

import (
	"context"
	"net/http"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/resolver"
)

func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

// resolverSchemaVersion is the schema version this binary expects, including
// the backend's own migrations.
func resolverSchemaVersion() int { return resolver.SchemaVersion() }
