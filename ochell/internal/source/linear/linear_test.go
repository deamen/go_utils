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
	if _, _, err := Parse([]byte(`{"type":"Issue","action":"update"}`)); !errors.Is(err, ErrIgnored) {
		t.Errorf("issue event should be ignored, got %v", err)
	}
	if _, _, err := Parse([]byte(`{"type":"AgentSessionEvent","action":"updated","agentSession":{"id":"s1"}}`)); !errors.Is(err, ErrIgnored) {
		t.Errorf("another action should be ignored, got %v", err)
	}
}

// A "prompted" event is a message from a person in a session that exists.
func TestParsePrompted(t *testing.T) {
	// The least a payload can hold: the session and the text.
	_, s, err := Parse([]byte(`{"type":"AgentSessionEvent","action":"prompted","agentSession":{"id":"s1"},"agentActivity":{"content":{"type":"prompt","body":"please also add tests"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Prompted || s.Prompt != "please also add tests" || s.SessionID != "s1" || s.Stop {
		t.Errorf("session = %+v", s)
	}
	// No issue in the payload: the caller finds the ticket by the session.
	if s.Key != "" {
		t.Errorf("key = %q, want none", s.Key)
	}

	// With the issue, and with the author of the prompt, who counts rather
	// than the creator of the session.
	_, s, err = Parse([]byte(`{"type":"AgentSessionEvent","action":"prompted",
		"agentSession":{"id":"s2","creator":{"id":"u-creator","email":"creator@example.com"},
			"issue":{"identifier":"ENG-7","title":"T","url":"https://linear.app/x/issue/ENG-7"}},
		"agentActivity":{"body":"use the second page","user":{"id":"u-author","email":"author@example.com"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Key != "ENG-7" || s.Prompt != "use the second page" || s.Actor != "u-author" || s.ActorEmail != "author@example.com" {
		t.Errorf("session = %+v", s)
	}
	_, s, _ = Parse([]byte(`{"type":"AgentSessionEvent","action":"prompted","agentSession":{"id":"s3","creator":{"id":"u-creator","email":"creator@example.com"}},"agentActivity":{"body":"x"}}`))
	if s.Actor != "u-creator" || s.ActorEmail != "creator@example.com" {
		t.Errorf("without an author the creator counts: %+v", s)
	}

	// The stop signal.
	_, s, err = Parse([]byte(`{"type":"AgentSessionEvent","action":"prompted","agentSession":{"id":"s4"},"agentActivity":{"signal":"stop","content":{"type":"prompt","body":"stop"}}}`))
	if err != nil || !s.Stop {
		t.Errorf("stop signal: %+v, %v", s, err)
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

func TestClosed(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		key  string
	}{
		"completed":     {`{"type":"Issue","action":"update","data":{"identifier":"ENG-1","state":{"type":"completed"}}}`, "ENG-1"},
		"cancelled":     {`{"type":"Issue","action":"update","data":{"identifier":"ENG-2","state":{"type":"canceled"}}}`, "ENG-2"},
		"removed":       {`{"type":"Issue","action":"remove","data":{"identifier":"ENG-3","state":{"type":"started"}}}`, "ENG-3"},
		"in progress":   {`{"type":"Issue","action":"update","data":{"identifier":"ENG-4","state":{"type":"started"}}}`, ""},
		"no state":      {`{"type":"Issue","action":"update","data":{"identifier":"ENG-5"}}`, ""},
		"no identifier": {`{"type":"Issue","action":"remove","data":{}}`, ""},
		"a comment":     {`{"type":"Comment","action":"create","data":{"identifier":"ENG-6","state":{"type":"completed"}}}`, ""},
	} {
		ev, _, err := Parse([]byte(c.body))
		if !errors.Is(err, ErrIgnored) || ev == nil {
			t.Fatalf("%s: Parse = %v, %v", name, ev, err)
		}
		if key, ok := ev.Closed(); key != c.key || ok != (c.key != "") {
			t.Errorf("%s: %q, %v; want %q", name, key, ok, c.key)
		}
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

func TestUndelegated(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		want bool
	}{
		"taken away":               {`{"type":"Issue","action":"update","appUserId":"app-1","data":{"identifier":"ENG-1"},"updatedFrom":{"delegateId":"app-1"}}`, true},
		"given to another agent":   {`{"type":"Issue","action":"update","appUserId":"app-1","data":{"identifier":"ENG-1","delegateId":"app-2"},"updatedFrom":{"delegateId":"app-1"}}`, true},
		"given to this agent":      {`{"type":"Issue","action":"update","appUserId":"app-1","data":{"identifier":"ENG-1","delegateId":"app-1"},"updatedFrom":{"delegateId":null}}`, false},
		"another agent lost it":    {`{"type":"Issue","action":"update","appUserId":"app-1","data":{"identifier":"ENG-1"},"updatedFrom":{"delegateId":"app-2"}}`, false},
		"another change":           {`{"type":"Issue","action":"update","appUserId":"app-1","data":{"identifier":"ENG-1","delegateId":"app-1"},"updatedFrom":{"title":"old"}}`, false},
		"nobody says whose it was": {`{"type":"Issue","action":"update","data":{"identifier":"ENG-1"},"updatedFrom":{"delegateId":"app-1"}}`, false},
		"a comment":                {`{"type":"Comment","action":"update","appUserId":"app-1","data":{"identifier":"ENG-1"},"updatedFrom":{"delegateId":"app-1"}}`, false},
	} {
		ev, _, err := Parse([]byte(c.body))
		if !errors.Is(err, ErrIgnored) || ev == nil {
			t.Fatalf("%s: Parse = %v, %v", name, ev, err)
		}
		if key, ok := ev.Undelegated(); ok != c.want || (ok && key != "ENG-1") {
			t.Errorf("%s: %q, %v; want %v", name, key, ok, c.want)
		}
	}
}
