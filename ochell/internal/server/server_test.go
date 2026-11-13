package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ochell/internal/auth"
	"ochell/internal/config"
	"ochell/internal/runner"
	"ochell/internal/source/linear"
	"ochell/internal/task"
)

const bot = "712020:digital-employee"

type fakeRunner struct {
	mu    sync.Mutex
	tasks []*task.Task
	err   error
}

func (f *fakeRunner) Submit(t *task.Task) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.tasks = append(f.tasks, t)
	return nil
}

func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Sources.JiraWebhook.Enabled = true
	cfg.Sources.JiraWebhook.Secret = "jira-secret"
	cfg.Sources.JiraWebhook.BotAccountID = bot
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = "auto-token"
	cfg.Sources.Linear.Enabled = true
	cfg.Sources.Linear.Secret = "linear-secret"
	return cfg
}

func newServer(t *testing.T, cfg *config.Config, r Submitter) *Server {
	t.Helper()
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func do(s *Server, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestJiraWebhook(t *testing.T) {
	fr := &fakeRunner{}
	s := newServer(t, testConfig(), fr)
	body := readFile(t, "jira-issue-assigned.json")
	sig := "sha256=" + auth.SignHex("jira-secret", []byte(body))

	if w := do(s, "/webhooks/jira", body, map[string]string{"X-Hub-Signature": "sha256=00"}); w.Code != 401 {
		t.Fatalf("bad signature: %d", w.Code)
	}
	if w := do(s, "/webhooks/jira", body, nil); w.Code != 401 {
		t.Fatalf("missing signature: %d", w.Code)
	}
	hdr := map[string]string{"X-Hub-Signature": sig, "X-Atlassian-Webhook-Identifier": "d-1"}
	if w := do(s, "/webhooks/jira", body, hdr); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued") {
		t.Fatalf("valid: %d %s", w.Code, w.Body)
	}
	if w := do(s, "/webhooks/jira", body, hdr); !strings.Contains(w.Body.String(), "duplicate") {
		t.Fatalf("retry should be de-duplicated: %s", w.Body)
	}
	if len(fr.tasks) != 1 || fr.tasks[0].Key != "DEV-42" || fr.tasks[0].URL == "" {
		t.Fatalf("tasks = %+v", fr.tasks)
	}

	other := strings.ReplaceAll(body, bot, "someone-else")
	osig := "sha256=" + auth.SignHex("jira-secret", []byte(other))
	if w := do(s, "/webhooks/jira", other, map[string]string{"X-Hub-Signature": osig}); w.Code != 200 || !strings.Contains(w.Body.String(), "ignored") {
		t.Fatalf("other assignee: %d %s", w.Code, w.Body)
	}
}

func TestJiraWebhookQueueFullAllowsRetry(t *testing.T) {
	fr := &fakeRunner{err: runner.ErrQueueFull}
	s := newServer(t, testConfig(), fr)
	body := readFile(t, "jira-issue-assigned.json")
	hdr := map[string]string{
		"X-Hub-Signature":                "sha256=" + auth.SignHex("jira-secret", []byte(body)),
		"X-Atlassian-Webhook-Identifier": "d-2",
	}
	if w := do(s, "/webhooks/jira", body, hdr); w.Code != 503 {
		t.Fatalf("queue full: %d", w.Code)
	}
	fr.err = nil
	if w := do(s, "/webhooks/jira", body, hdr); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued") {
		t.Fatalf("retry after 503 must be accepted: %d %s", w.Code, w.Body)
	}
}

func TestJiraAutomation(t *testing.T) {
	fr := &fakeRunner{}
	s := newServer(t, testConfig(), fr)
	body := readFile(t, "jira-automation.json")
	if w := do(s, "/webhooks/jira-automation", body, map[string]string{"Authorization": "Bearer nope"}); w.Code != 401 {
		t.Fatalf("bad token: %d", w.Code)
	}
	if w := do(s, "/webhooks/jira-automation", body, map[string]string{"Authorization": "Bearer auto-token"}); w.Code != 200 {
		t.Fatalf("valid: %d %s", w.Code, w.Body)
	}
	bad := `{"issueKey":"../../etc/passwd"}`
	if w := do(s, "/webhooks/jira-automation", bad, map[string]string{"Authorization": "Bearer auto-token"}); w.Code != 400 {
		t.Fatalf("path traversal key: %d", w.Code)
	}
	if len(fr.tasks) != 1 || fr.tasks[0].Key != "DEV-42" {
		t.Fatalf("tasks = %+v", fr.tasks)
	}
}

func TestJiraAutomationWithoutAssignee(t *testing.T) {
	cfg := testConfig()
	cfg.Sources.JiraAutomation.BotAccountID = bot
	fr := &fakeRunner{}
	s := newServer(t, cfg, fr)
	hdr := map[string]string{"Authorization": "Bearer auto-token"}
	for _, body := range []string{
		`{"issueKey":"DEV-42","summary":"s"}`,
		`{"issueKey":"DEV-42","assigneeAccountId":""}`,
		`{"issue":{"key":"DEV-42","fields":{"assignee":null}}}`,
	} {
		w := do(s, "/webhooks/jira-automation", body, hdr)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "no assignee") {
			t.Errorf("%s: %d %s, want 400", body, w.Code, w.Body)
		}
	}
	if w := do(s, "/webhooks/jira-automation", `{"issueKey":"DEV-42","assigneeAccountId":"someone-else"}`, hdr); w.Code != 200 || !strings.Contains(w.Body.String(), "ignored") {
		t.Errorf("other assignee: %d %s, want 200 ignored", w.Code, w.Body)
	}
	if len(fr.tasks) != 0 {
		t.Fatalf("a run was started without the bot as assignee: %+v", fr.tasks)
	}
	if w := do(s, "/webhooks/jira-automation", readFile(t, "jira-automation.json"), hdr); w.Code != 200 || len(fr.tasks) != 1 {
		t.Errorf("payload that names the bot: %d %s, tasks %d", w.Code, w.Body, len(fr.tasks))
	}
}

func TestMethodAndUnknownPath(t *testing.T) {
	s := newServer(t, testConfig(), &fakeRunner{})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/webhooks/jira", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET webhook: %d", w.Code)
	}
	if w := do(s, "/nope", "{}", nil); w.Code != 404 {
		t.Errorf("unknown path: %d", w.Code)
	}
}

// fakeLinearAPI records GraphQL calls made by the server.
type fakeLinearAPI struct {
	mu    sync.Mutex
	calls []map[string]any
	got   chan struct{}
}

func (f *fakeLinearAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer access-1" {
		w.WriteHeader(401)
		w.Write([]byte(`{"errors":[{"message":"auth"}]}`))
		return
	}
	var req map[string]any
	json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	f.calls = append(f.calls, req)
	f.mu.Unlock()
	w.Write([]byte(`{"data":{"agentActivityCreate":{"success":true}}}`))
	f.got <- struct{}{}
}

func TestLinearAgentSession(t *testing.T) {
	api := &fakeLinearAPI{got: make(chan struct{}, 4)}
	apiSrv := httptest.NewServer(api)
	defer apiSrv.Close()

	cfg := testConfig()
	cfg.Sources.Linear.ClientID = "cid"
	cfg.Sources.Linear.ClientSecret = "csecret"
	cfg.Sources.Linear.TokenFile = filepath.Join(t.TempDir(), "token.json")
	fr := &fakeRunner{}
	s := newServer(t, cfg, fr)
	s.linear.APIURL = apiSrv.URL
	if err := s.linear.SaveToken(&linear.Token{AccessToken: "access-1"}); err != nil {
		t.Fatal(err)
	}

	body := strings.Replace(readFile(t, "linear-agent-session-created.json"), `"webhookTimestamp": 0`,
		`"webhookTimestamp": `+strconv.FormatInt(time.Now().UnixMilli(), 10), 1)
	sig := auth.SignHex("linear-secret", []byte(body))

	if w := do(s, "/webhooks/linear", body, map[string]string{"Linear-Signature": "00"}); w.Code != 401 {
		t.Fatalf("bad signature: %d", w.Code)
	}
	w := do(s, "/webhooks/linear", body, map[string]string{"Linear-Signature": sig, "Linear-Delivery": "ld-1"})
	if w.Code != 200 {
		t.Fatalf("valid: %d %s", w.Code, w.Body)
	}
	select {
	case <-api.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no acknowledgement activity posted")
	}
	if len(fr.tasks) != 1 {
		t.Fatalf("tasks = %d", len(fr.tasks))
	}
	tk := fr.tasks[0]
	if tk.Key != "ENG-123" || !strings.Contains(tk.Context, "<issue") || tk.OnFinish == nil {
		t.Fatalf("task = %+v", tk)
	}
	if err := tk.OnFinish(context.Background(), tk, task.Result{Tail: "Opened PR #7"}); err != nil {
		t.Fatal(err)
	}
	<-api.got

	api.mu.Lock()
	defer api.mu.Unlock()
	kinds := []string{}
	for _, c := range api.calls {
		in := c["variables"].(map[string]any)["input"].(map[string]any)
		if in["agentSessionId"] != "session-0000" {
			t.Errorf("wrong session id in %v", in)
		}
		kinds = append(kinds, in["content"].(map[string]any)["type"].(string))
	}
	if strings.Join(kinds, ",") != "thought,response" {
		t.Errorf("activities = %v", kinds)
	}
}

// A second session on a ticket that is already queued or running starts no
// run, but gets an answer, so Linear does not show it as unresponsive.
func TestLinearSecondSessionOnBusyTicket(t *testing.T) {
	api := &fakeLinearAPI{got: make(chan struct{}, 4)}
	apiSrv := httptest.NewServer(api)
	defer apiSrv.Close()

	cfg := testConfig()
	cfg.Sources.Linear.ClientID = "cid"
	cfg.Sources.Linear.ClientSecret = "csecret"
	cfg.Sources.Linear.TokenFile = filepath.Join(t.TempDir(), "token.json")
	cfg.Sources.Linear.APIURL = apiSrv.URL
	fr := &fakeRunner{err: runner.ErrBusy}
	s := newServer(t, cfg, fr)
	if err := s.linear.SaveToken(&linear.Token{AccessToken: "access-1"}); err != nil {
		t.Fatal(err)
	}

	body := strings.Replace(readFile(t, "linear-agent-session-created.json"), `"webhookTimestamp": 0`,
		`"webhookTimestamp": `+strconv.FormatInt(time.Now().UnixMilli(), 10), 1)
	hdr := map[string]string{"Linear-Signature": auth.SignHex("linear-secret", []byte(body)), "Linear-Delivery": "ld-busy"}
	w := do(s, "/webhooks/linear", body, hdr)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "already in progress") {
		t.Fatalf("busy ticket: %d %s", w.Code, w.Body)
	}
	select {
	case <-api.got:
	case <-time.After(5 * time.Second):
		t.Fatal("the second session got no activity")
	}
	api.mu.Lock()
	in := api.calls[0]["variables"].(map[string]any)["input"].(map[string]any)
	api.mu.Unlock()
	content := in["content"].(map[string]any)
	if in["agentSessionId"] != "session-0000" || content["type"] != "response" || !strings.Contains(content["body"].(string), "ENG-123 is already being worked on") {
		t.Errorf("activity = %v", in)
	}

	// The delivery was handled: a retry of it must not post a second answer.
	if w := do(s, "/webhooks/linear", body, hdr); !strings.Contains(w.Body.String(), "duplicate") {
		t.Errorf("retried delivery: %d %s, want duplicate", w.Code, w.Body)
	}
	select {
	case <-api.got:
		t.Error("a retried delivery posted a second activity")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestLastN(t *testing.T) {
	if got := lastN("héllo", 4); got != "…llo" {
		t.Errorf("lastN = %q", got)
	}
	if got := lastN("abc", 10); got != "abc" {
		t.Errorf("lastN = %q", got)
	}
}
