package backend

import (
	"errors"
	"net/http"
	"time"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ip := clientIP(r)

	// Throttle before touching the password, and count by email and by source
	// separately: email-only throttling lets one host spray many accounts,
	// source-only lets a distributed attempt through against one account.
	byEmail, byIP, err := s.store.RecentFailures(in.Email, ip, s.cfg.LoginWindow)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	if byEmail >= s.cfg.MaxLoginFailures || byIP >= s.cfg.MaxLoginFailures*3 {
		s.store.Record(AuditEntry{
			ActorType: "anonymous", ActorLabel: in.Email,
			Action: ActionLoginFailed, IP: ip,
			Detail:    AuditDetail(map[string]any{"reason": "throttled"}),
			RequestID: RequestIDFrom(r.Context()),
		})
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}

	user, err := s.store.UserByEmail(in.Email)
	if err == nil && user.Active() {
		err = VerifyPassword(in.Password, user.passwordHash)
	} else if err == nil {
		err = ErrInvalidCredentials // account disabled
	} else {
		// Spend the time an argon2 verification would take, so a missing
		// account is not distinguishable from a wrong password by timing.
		_ = VerifyPassword(in.Password, dummyHash)
		err = ErrInvalidCredentials
	}

	if err != nil {
		s.store.RecordLoginAttempt(in.Email, ip, false)
		s.store.Record(AuditEntry{
			ActorType: "anonymous", ActorLabel: in.Email,
			Action: ActionLoginFailed, IP: ip,
			RequestID: RequestIDFrom(r.Context()),
		})
		// One message for every failure mode: no account enumeration.
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, sess, err := s.store.CreateSession(user.ID, s.cfg.SessionTTL, ip, r.UserAgent())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	s.store.RecordLoginAttempt(in.Email, ip, true)
	s.store.touchLogin(user.ID)
	s.store.Record(AuditEntry{
		ActorType: "user", ActorID: itoa(user.ID), ActorLabel: user.Email,
		Action: ActionLogin, IP: ip, RequestID: RequestIDFrom(r.Context()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: token,
		Path:  "/",
		// HttpOnly keeps the session out of reach of any script, so an XSS
		// elsewhere on the origin cannot steal it. SameSite=Lax is a second
		// layer under the CSRF token.
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(sess.ExpiresAt, 0),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id": user.ID, "email": user.Email, "name": user.Name, "role": user.Role,
		},
		// The CSRF token is returned in the body, not a cookie: the client
		// must be able to read it to echo it back, which is the whole point.
		"csrf_token": sess.CSRFToken,
		"expires_at": sess.ExpiresAt,
	})
}

// dummyHash is a valid argon2id hash of an unguessable value. Verifying
// against it costs the same as a real check, which is what keeps login timing
// from revealing whether an account exists.
var dummyHash = "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$" +
	"Q6mQpMDBHRQ0Q4dnMxwGVGx9pXn6mZ0kQGxN8vFqZ0g"

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = s.store.DeleteSession(c.Value)
	}
	if p := PrincipalFrom(r.Context()); p != nil {
		s.store.Record(AuditEntry{
			ActorType: "user", ActorID: itoa(p.UserID), ActorLabel: p.Email,
			Action: ActionLogout, IP: clientIP(r), RequestID: RequestIDFrom(r.Context()),
		})
	}

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	scopes := make([]string, 0, len(p.Scopes))
	for _, sc := range AllScopes {
		if p.Scopes[sc] {
			scopes = append(scopes, string(sc))
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id": p.UserID, "email": p.Email, "role": p.Role,
		"auth": p.Kind, "scopes": scopes,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := s.store.UserByID(p.UserID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	// Requiring the current password stops a stolen session being upgraded
	// into permanent account control.
	if err := VerifyPassword(in.Current, user.passwordHash); err != nil {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	if err := s.store.SetUserPassword(p.UserID, in.New); err != nil {
		if errors.Is(err, ErrPasswordTooShort) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	// Every other session for this account is invalidated: a password change
	// is how someone reacts to a suspected compromise, and it must actually
	// evict the intruder.
	_ = s.store.DeleteUserSessions(p.UserID)

	s.store.Record(AuditEntry{
		ActorType: "user", ActorID: itoa(p.UserID), ActorLabel: p.Email,
		Action: ActionUserPassword, TargetType: "user", TargetID: itoa(p.UserID),
		IP: clientIP(r), RequestID: RequestIDFrom(r.Context()),
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "password changed; all sessions signed out",
	})
}
