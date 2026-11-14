package linear

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"ochell/internal/auth"
)

func sample(t *testing.T, ts time.Time) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/linear-agent-session-created.json")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(string(raw), `"webhookTimestamp": 0`,
		`"webhookTimestamp": `+strconv.FormatInt(ts.UnixMilli(), 10), 1))
}

func TestVerify(t *testing.T) {
	now := time.Now()
	body := sample(t, now)
	sig := auth.SignHex("sec", body)
	if err := Verify("sec", body, sig, time.Minute, now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := Verify("other", body, sig, time.Minute, now); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong secret: got %v", err)
	}
	if err := Verify("sec", body, sig, time.Minute, now.Add(2*time.Minute)); !errors.Is(err, ErrStale) {
		t.Errorf("replay: got %v", err)
	}
}

func TestParse(t *testing.T) {
	ev, s, err := Parse(sample(t, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if s.SessionID != "session-0000" || s.Key != "ENG-123" || !strings.Contains(s.Context, "ENG-123") || ev.OrganizationID != "org-0000" {
		t.Errorf("unexpected session %+v", s)
	}
	prompted := `{"type":"AgentSessionEvent","action":"prompted","agentSession":{"id":"s1"},"agentActivity":{"content":{"type":"prompt","body":"please also add tests"}}}`
	ev, _, err = Parse([]byte(prompted))
	if !errors.Is(err, ErrIgnored) || ev.PromptText() != "please also add tests" {
		t.Errorf("prompted: err=%v text=%q", err, ev.PromptText())
	}
	if _, _, err := Parse([]byte(`{"type":"Issue","action":"update"}`)); !errors.Is(err, ErrIgnored) {
		t.Errorf("issue event should be ignored, got %v", err)
	}
}

// A session that a comment started carries that comment.
func TestParseComment(t *testing.T) {
	body := `{"type":"AgentSessionEvent","action":"created","agentSession":{"id":"s-1",
		"issue":{"identifier":"ENG-1","title":"T","url":"https://linear.app/x/issue/ENG-1"},
		"comment":{"id":"c-1","body":"@agent please fix the typo too"}}}`
	_, sess, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if sess.Comment != "@agent please fix the typo too" || sess.Key != "ENG-1" {
		t.Errorf("session = %+v", sess)
	}
}

func TestState(t *testing.T) {
	st := NewState("secret", time.Minute)
	if err := VerifyState("secret", st, time.Now()); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	if err := VerifyState("other", st, time.Now()); err == nil {
		t.Error("state with wrong secret accepted")
	}
	if err := VerifyState("secret", st, time.Now().Add(2*time.Minute)); err == nil {
		t.Error("expired state accepted")
	}
	if err := VerifyState("secret", "garbage", time.Now()); err == nil {
		t.Error("garbage state accepted")
	}
}

func TestAuthorizeURL(t *testing.T) {
	u := AuthorizeURL("cid", "https://x.ngrok-free.app/oauth/linear/callback", "st")
	for _, want := range []string{"actor=app", "app%3Aassignable", "app%3Amentionable", "client_id=cid", "state=st"} {
		if !strings.Contains(u, want) {
			t.Errorf("%s missing %s", u, want)
		}
	}
}
