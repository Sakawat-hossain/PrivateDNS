package backend

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPasswordTooShort   = errors.New("password must be at least 12 characters")
	ErrMalformedHash      = errors.New("stored password hash is malformed")
)

// Argon2id parameters.
//
// These are the values OWASP recommends as a baseline: 19 MiB of memory, two
// passes, one degree of parallelism. Memory cost is what makes the hash
// expensive to attack on a GPU, which is why it is the parameter to raise
// first if this ever needs strengthening.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16

	// minPasswordLen is deliberately length-only. Composition rules ("one
	// symbol, one digit") push people toward predictable substitutions and
	// measurably weaken the result.
	minPasswordLen = 12
)

// HashPassword returns an encoded argon2id hash, self-describing so the
// parameters can be raised later without invalidating existing hashes.
func HashPassword(password string) (string, error) {
	if len(password) < minPasswordLen {
		return "", ErrPasswordTooShort
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
func VerifyPassword(password, encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return ErrMalformedHash
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return ErrMalformedHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrMalformedHash
	}

	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// ---- opaque secrets ----

// tokenBytes is the entropy behind session cookies and API tokens. 32 bytes is
// far beyond guessing range and keeps the encoded form a manageable length.
const tokenBytes = 32

// newSecret returns a URL-safe random string.
func newSecret() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashSecret is the one-way transform applied before a session or token value
// is stored.
//
// SHA-256 rather than argon2 here, deliberately: these values are 32 bytes of
// machine-generated entropy, not human-chosen passwords, so there is no
// dictionary to attack and no reason to pay a slow-hash cost on every request.
// What matters is that a database disclosure yields no usable credentials.
func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// APITokenPrefix identifies our tokens in logs and secret scanners.
//
// The prefix is deliberate: GitHub's secret scanning and similar tools match on
// recognisable prefixes, so a token accidentally committed is more likely to be
// caught and reported.
const APITokenPrefix = "pdns_"

// prefixLen is how much of a token is stored in clear, enough to look the
// record up without revealing the secret.
const prefixLen = 12

// NewAPIToken returns the value to hand the caller once, plus the prefix and
// hash to store. The full value is never persisted and cannot be recovered.
func NewAPIToken() (token, prefix, hash string, err error) {
	secret, err := newSecret()
	if err != nil {
		return "", "", "", err
	}
	token = APITokenPrefix + secret
	if len(token) < prefixLen {
		return "", "", "", errors.New("generated token is too short")
	}
	return token, token[:prefixLen], hashSecret(token), nil
}

// TokenPrefix extracts the lookup prefix from a presented token.
func TokenPrefix(token string) (string, bool) {
	if !strings.HasPrefix(token, APITokenPrefix) || len(token) < prefixLen {
		return "", false
	}
	return token[:prefixLen], true
}
