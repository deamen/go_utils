package auth

import (
	"net/http/httptest"
	"testing"
)

// Test vector from https://developer.atlassian.com/cloud/jira/platform/webhooks/
func TestVerifyHubSignatureAtlassianVector(t *testing.T) {
	const (
		secret = "It's a Secret to Everybody"
		body   = "Hello World!"
		sig    = "a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9"
	)
	if got := SignHex(secret, []byte(body)); got != sig {
		t.Fatalf("SignHex = %s, want %s", got, sig)
	}
	if err := VerifyHubSignature(secret, []byte(body), "sha256="+sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	for _, h := range []string{"", "sha256=00", "sha1=" + sig, sig, "sha256=zz"} {
		if err := VerifyHubSignature(secret, []byte(body), h); err == nil {
			t.Errorf("header %q accepted", h)
		}
	}
	if err := VerifyHubSignature(secret, []byte(body+" "), "sha256="+sig); err != ErrMismatch {
		t.Errorf("tampered body: got %v, want ErrMismatch", err)
	}
}

func TestVerifyToken(t *testing.T) {
	cases := []struct {
		header, value string
		ok            bool
	}{
		{"Authorization", "Bearer s3cret", true},
		{"Authorization", "bearer s3cret", true},
		{"Authorization", "s3cret", true},
		{"Authorization", "Bearer wrong", false},
		{"Authorization", "", false},
		{"X-Orchestrator-Token", "s3cret", true},
		{"X-Orchestrator-Token", "Bearer s3cret", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		if c.value != "" {
			r.Header.Set(c.header, c.value)
		}
		err := VerifyToken(r, c.header, "s3cret")
		if (err == nil) != c.ok {
			t.Errorf("%s=%q: err=%v, want ok=%v", c.header, c.value, err, c.ok)
		}
	}
}
