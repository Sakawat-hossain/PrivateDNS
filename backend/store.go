package backend

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
	ErrForbidden = errors.New("forbidden")
)

// Store is the backend's data access layer. It shares the resolver's database
// file: one source of truth about who has paid, readable by both tiers.
type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) DB() *sql.DB { return s.db }

// ---- users ----

type User struct {
	ID           int64  `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	Role         Role   `json:"role"`
	Status       string `json:"status"`
	CustomerID   int64  `json:"customer_id,omitempty"`
	CreatedAt    int64  `json:"created_at"`
	LastLoginAt  int64  `json:"last_login_at"`
	passwordHash string
}

func (u *User) Active() bool { return u != nil && u.Status == "active" }

func (s *Store) CreateUser(email, name, password string, role Role) (*User, error) {
	return s.createUser(email, name, password, role, 0)
}

// CreateCustomerUser creates a login for a customer record. The link is
// explicit because users and customers are separate tables with independent id
// sequences; comparing one id against the other would grant access across
// unrelated accounts that happened to collide.
func (s *Store) CreateCustomerUser(email, name, password string, customerID int64) (*User, error) {
	return s.createUser(email, name, password, RoleCustomer, customerID)
}

func (s *Store) createUser(email, name, password string, role Role, customerID int64) (*User, error) {
	if !role.Valid() {
		return nil, fmt.Errorf("invalid role %q", role)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	email = strings.ToLower(strings.TrimSpace(email))
	now := time.Now().Unix()

	res, err := s.db.Exec(
		`INSERT INTO users (email,name,password_hash,role,status,customer_id,created_at,updated_at)
		 VALUES (?,?,?,?,'active',?,?,?)`,
		email, name, hash, string(role), customerID, now, now)
	if err != nil {
		if isUnique(err) {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	id, _ := res.LastInsertId()

	return &User{ID: id, Email: email, Name: name, Role: role, Status: "active",
		CustomerID: customerID, CreatedAt: now}, nil
}

func (s *Store) UserByEmail(email string) (*User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id,email,name,password_hash,role,status,customer_id,created_at,last_login_at
		 FROM users WHERE email=?`, strings.ToLower(strings.TrimSpace(email))))
}

func (s *Store) UserByID(id int64) (*User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id,email,name,password_hash,role,status,customer_id,created_at,last_login_at
		 FROM users WHERE id=?`, id))
}

func (s *Store) scanUser(row *sql.Row) (*User, error) {
	var u User
	var role string
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.passwordHash, &role, &u.Status, &u.CustomerID, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Role = Role(role)
	return &u, nil
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(
		`SELECT id,email,name,role,status,created_at,last_login_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*User
	for rows.Next() {
		var u User
		var role string
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &role, &u.Status, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		u.Role = Role(role)
		out = append(out, &u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserPassword(id int64, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET password_hash=?, updated_at=? WHERE id=?`,
		hash, time.Now().Unix(), id)
	return err
}

func (s *Store) SetUserStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE users SET status=?, updated_at=? WHERE id=?`,
		status, time.Now().Unix(), id)
	return err
}

func (s *Store) touchLogin(id int64) {
	_, _ = s.db.Exec(`UPDATE users SET last_login_at=? WHERE id=?`, time.Now().Unix(), id)
}

// CountUsers reports how many accounts exist, used to decide whether the
// first-run bootstrap should offer to create an administrator.
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ---- sessions ----

type Session struct {
	UserID    int64
	CSRFToken string
	ExpiresAt int64
}

func (s *Store) CreateSession(userID int64, ttl time.Duration, ip, userAgent string) (token string, sess *Session, err error) {
	token, err = newSecret()
	if err != nil {
		return "", nil, err
	}
	csrf, err := newSecret()
	if err != nil {
		return "", nil, err
	}

	now := time.Now()
	expires := now.Add(ttl).Unix()

	_, err = s.db.Exec(
		`INSERT INTO sessions (token_hash,user_id,csrf_token,user_agent,ip,created_at,expires_at)
		 VALUES (?,?,?,?,?,?,?)`,
		hashSecret(token), userID, csrf, truncate(userAgent, 256), ip, now.Unix(), expires)
	if err != nil {
		return "", nil, err
	}

	return token, &Session{UserID: userID, CSRFToken: csrf, ExpiresAt: expires}, nil
}

func (s *Store) SessionByToken(token string) (*Session, error) {
	var sess Session
	err := s.db.QueryRow(
		`SELECT user_id,csrf_token,expires_at FROM sessions WHERE token_hash=?`,
		hashSecret(token),
	).Scan(&sess.UserID, &sess.CSRFToken, &sess.ExpiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if sess.ExpiresAt <= time.Now().Unix() {
		// Clean up as we go rather than relying solely on the sweeper.
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, hashSecret(token))
		return nil, ErrNotFound
	}
	return &sess, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, hashSecret(token))
	return err
}

func (s *Store) DeleteUserSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

func (s *Store) PurgeExpiredSessions() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- API tokens ----

type APIToken struct {
	ID         int64  `json:"id"`
	Prefix     string `json:"prefix"`
	Name       string `json:"name"`
	UserID     int64  `json:"user_id"`
	Scopes     string `json:"scopes"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
	LastUsedAt int64  `json:"last_used_at"`
	RevokedAt  int64  `json:"revoked_at"`
}

func (t *APIToken) Usable(now int64) bool {
	if t == nil || t.RevokedAt != 0 {
		return false
	}
	return t.ExpiresAt == 0 || t.ExpiresAt > now
}

func (s *Store) CreateAPIToken(userID int64, name string, scopes map[Scope]bool, ttl time.Duration) (plaintext string, tok *APIToken, err error) {
	plaintext, prefix, hash, err := NewAPIToken()
	if err != nil {
		return "", nil, err
	}

	now := time.Now()
	var expires int64
	if ttl > 0 {
		expires = now.Add(ttl).Unix()
	}
	scopeStr := FormatScopes(scopes)

	res, err := s.db.Exec(
		`INSERT INTO api_tokens (prefix,token_hash,name,user_id,scopes,created_at,expires_at)
		 VALUES (?,?,?,?,?,?,?)`,
		prefix, hash, name, userID, scopeStr, now.Unix(), expires)
	if err != nil {
		return "", nil, err
	}
	id, _ := res.LastInsertId()

	return plaintext, &APIToken{
		ID: id, Prefix: prefix, Name: name, UserID: userID,
		Scopes: scopeStr, CreatedAt: now.Unix(), ExpiresAt: expires,
	}, nil
}

// APITokenByValue looks a token up by its prefix and verifies the hash.
func (s *Store) APITokenByValue(value string) (*APIToken, error) {
	prefix, ok := TokenPrefix(value)
	if !ok {
		return nil, ErrNotFound
	}

	var t APIToken
	var storedHash string
	err := s.db.QueryRow(
		`SELECT id,prefix,token_hash,name,user_id,scopes,created_at,expires_at,last_used_at,revoked_at
		 FROM api_tokens WHERE prefix=?`, prefix,
	).Scan(&t.ID, &t.Prefix, &storedHash, &t.Name, &t.UserID, &t.Scopes,
		&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if !constantTimeEqual(storedHash, hashSecret(value)) {
		return nil, ErrNotFound
	}
	return &t, nil
}

func (s *Store) TouchAPIToken(id int64) {
	_, _ = s.db.Exec(`UPDATE api_tokens SET last_used_at=? WHERE id=?`, time.Now().Unix(), id)
}

func (s *Store) RevokeAPIToken(id int64, ownerID int64, isAdmin bool) error {
	var owner int64
	err := s.db.QueryRow(`SELECT user_id FROM api_tokens WHERE id=?`, id).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !isAdmin && owner != ownerID {
		return ErrForbidden
	}
	_, err = s.db.Exec(`UPDATE api_tokens SET revoked_at=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

func (s *Store) ListAPITokens(userID int64, isAdmin bool) ([]*APIToken, error) {
	query := `SELECT id,prefix,name,user_id,scopes,created_at,expires_at,last_used_at,revoked_at
	          FROM api_tokens`
	args := []any{}
	if !isAdmin {
		query += ` WHERE user_id=?`
		args = append(args, userID)
	}
	query += ` ORDER BY id DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Prefix, &t.Name, &t.UserID, &t.Scopes,
			&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// ---- login throttling ----

func (s *Store) RecordLoginAttempt(email, ip string, ok bool) {
	v := 0
	if ok {
		v = 1
	}
	_, _ = s.db.Exec(`INSERT INTO login_attempts (email,ip,succeeded,at) VALUES (?,?,?,?)`,
		strings.ToLower(email), ip, v, time.Now().Unix())
}

// RecentFailures counts failed attempts against an identity in a window.
//
// Counting by email and by IP separately matters: throttling only on email lets
// an attacker spray many accounts from one host, and throttling only on IP lets
// a distributed attempt through against a single account.
func (s *Store) RecentFailures(email, ip string, window time.Duration) (byEmail, byIP int, err error) {
	since := time.Now().Add(-window).Unix()

	err = s.db.QueryRow(
		`SELECT COUNT(*) FROM login_attempts WHERE email=? AND succeeded=0 AND at>=?`,
		strings.ToLower(email), since).Scan(&byEmail)
	if err != nil {
		return 0, 0, err
	}
	err = s.db.QueryRow(
		`SELECT COUNT(*) FROM login_attempts WHERE ip=? AND succeeded=0 AND at>=?`,
		ip, since).Scan(&byIP)
	return byEmail, byIP, err
}

func (s *Store) PurgeOldLoginAttempts(olderThan time.Duration) error {
	_, err := s.db.Exec(`DELETE FROM login_attempts WHERE at < ?`,
		time.Now().Add(-olderThan).Unix())
	return err
}

// ---- helpers ----

func isUnique(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
