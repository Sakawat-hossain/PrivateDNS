package portal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
)

// The diagnostic answers the question every support conversation starts with:
// "I set it up but it isn't working."
//
// A web page cannot read the system resolver. What it can do is ask for a
// hostname nobody has ever looked up before and see whether that query reaches
// us. If it does, this device's DNS is ours. If it does not, it is not — and
// that single fact resolves most of those conversations without a message.
//
// The nonce is one-use. Reading a result consumes it, so a value cannot be
// replayed to make a second device look configured.

func (s *Server) handleCheckPage(w http.ResponseWriter, r *http.Request) {
	d := pageData{ClientIP: backend.ClientIP(r)}
	if sess := s.sessionFrom(r); sess != nil {
		d.SignedIn = true
		d.CSRF = sess.csrf
		if id := sess.primaryTenant(); id != "" {
			d.RouteID = id
			d.Hostname = id + "." + s.cfg.BaseDomain
		}
	}
	s.render(w, r, "check.html", d)
}

// handleCheckStart issues a nonce and tells the page which hostname to resolve.
func (s *Server) handleCheckStart(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "could not start check", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(buf)

	writeJSON(w, http.StatusOK, map[string]any{
		"nonce": nonce,
		// Resolving this name is the whole test. The connection that follows
		// is expected to fail; only the lookup matters.
		"probe_host": nonce + ".check." + s.cfg.BaseDomain,
	})
}

// handleCheckResult asks the resolver whether the probe arrived.
func (s *Server) handleCheckResult(w http.ResponseWriter, r *http.Request) {
	nonce := r.PathValue("nonce")
	if !validNonce(nonce) {
		http.Error(w, "invalid nonce", http.StatusBadRequest)
		return
	}

	res, err := s.readProbe(r.Context(), nonce)
	if err != nil {
		s.log.Error("probe readback failed", "err", err)
		writeJSON(w, http.StatusOK, map[string]any{
			"found": false, "error": "resolver unreachable",
		})
		return
	}

	lang := LangFrom(r)
	out := map[string]any{
		"found":     res.Found,
		"client_ip": backend.ClientIP(r),
	}

	if !res.Found {
		out["message"] = T(lang, "check.notusing")
		out["fixes"] = []string{
			T(lang, "check.fix1"), T(lang, "check.fix2"), T(lang, "check.fix3"),
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	out["message"] = T(lang, "check.using")
	out["protocol"] = protocolLabel(res.Protocol)

	// Reporting the tenant only to its owner. The probe reveals which
	// subscription a device is using, which is not something a stranger on the
	// same page should learn.
	if sess := s.sessionFrom(r); sess != nil && sess.owns(res.RouteID) {
		out["route_id"] = res.RouteID
		out["hostname"] = res.RouteID + "." + s.cfg.BaseDomain

		if t := s.policy.Tenant(res.RouteID); t != nil {
			now := time.Now().Unix()
			out["active"] = t.Active(now)
			out["filtering"] = t.Filtering(now)
			out["expires_at"] = t.ExpiresAt
		}
	}

	writeJSON(w, http.StatusOK, out)
}

func protocolLabel(via string) string {
	switch via {
	case "sni":
		return "DNS-over-TLS" // identified from the TLS handshake
	case "ip":
		return "Plain DNS"
	}
	return via
}

// probeResult mirrors what the resolver's admin API returns.
type probeResult struct {
	Found    bool   `json:"found"`
	RouteID  string `json:"route_id"`
	Protocol string `json:"protocol"`
	At       int64  `json:"at"`
}

// readProbe queries the resolver's admin API.
//
// The portal and the resolver are separate processes, so the result has to
// cross a boundary. HTTP to the resolver's loopback admin API is used rather
// than a shared table, because a probe is worthless after a minute and writing
// one per diagnostic would put the DNS query path on a disk write.
func (s *Server) readProbe(ctx interface{ Done() <-chan struct{} }, nonce string) (probeResult, error) {
	var out probeResult

	if s.cfg.ResolverAdmin == "" {
		return out, fmt.Errorf("resolver_admin is not configured")
	}

	url := strings.TrimRight(s.cfg.ResolverAdmin, "/") + "/v1/probes/" + nonce
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return out, err
	}
	if s.cfg.ResolverToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.ResolverToken)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("resolver returned %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// validNonce guards the value before it is placed in a URL path.
func validNonce(n string) bool {
	if len(n) != 24 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
