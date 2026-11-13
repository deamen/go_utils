// Package auth verifies webhook requests: HMAC signatures and shared tokens.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

var (
	ErrMissing  = errors.New("missing credential")
	ErrMismatch = errors.New("credential mismatch")
	ErrFormat   = errors.New("malformed credential")
)

// SignHex returns the hex encoded HMAC-SHA256 of body.
func SignHex(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyHex compares a hex HMAC-SHA256 signature of body in constant time.
func VerifyHex(secret string, body []byte, sigHex string) error {
	if sigHex == "" {
		return ErrMissing
	}
	got, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return ErrFormat
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	if !hmac.Equal(got, m.Sum(nil)) {
		return ErrMismatch
	}
	return nil
}

// VerifyHubSignature verifies an Atlassian "X-Hub-Signature: sha256=<hex>" header.
func VerifyHubSignature(secret string, body []byte, header string) error {
	if header == "" {
		return ErrMissing
	}
	method, sig, ok := strings.Cut(header, "=")
	if !ok || !strings.EqualFold(method, "sha256") {
		return ErrFormat
	}
	return VerifyHex(secret, body, sig)
}

// VerifyToken checks a shared token carried in the named header. For the
// Authorization header a "Bearer " prefix is accepted.
func VerifyToken(r *http.Request, header, token string) error {
	v := r.Header.Get(header)
	if v == "" {
		return ErrMissing
	}
	if strings.EqualFold(header, "Authorization") {
		if scheme, rest, ok := strings.Cut(v, " "); ok && strings.EqualFold(scheme, "Bearer") {
			v = strings.TrimSpace(rest)
		}
	}
	// Hash both sides so the comparison does not leak the token length.
	a, b := sha256.Sum256([]byte(v)), sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return ErrMismatch
	}
	return nil
}
