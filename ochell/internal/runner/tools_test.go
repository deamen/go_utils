package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ochell/internal/mcp"
	"ochell/internal/policy"
	"ochell/internal/task"
	"ochell/internal/tracker"
)

// ticketTool calls one of ochell's ticket tools and returns the status and
// the answer on one line.
func ticketTool(url, token, tool string, args map[string]any) string {
	if args == nil {
		args = map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

// oneTicket is a tracker with one ticket.
type oneTicket struct {
	mu       sync.Mutex
	comments []string
}

func (o *oneTicket) Ticket(_ context.Context, key string) (tracker.Ticket, error) {
	return tracker.Ticket{Key: key, Title: "The title", Description: "What the ticket asks for."}, nil
}

func (o *oneTicket) Comment(_ context.Context, key, body string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.comments = append(o.comments, key+": "+body)
	return nil
}

// A run of a tier with the ticket tools reaches its ticket through ochell,
// with a token that is its own, is never written down, and opens nothing
// when the run has ended.
func TestTicketTools(t *testing.T) {
	tr := &oneTicket{}
	tools := mcp.New("test", logger())
	tools.Use("jira", tr)
	srv := httptest.NewServer(tools)
	defer srv.Close()

	cfg := agentCfg(t, "ticket")
	cfg.PromptVia = "stdin"
	cfg.PromptTemplate = "{{if .TicketTools}}tools{{else}}twg{{end}} for {{.Key}}\n{{.RunContext}}"
	r, err := New(cfg, logger(), testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse([]byte("tiers:\n  - {name: plain}\n  - {name: tools, grants: {ticket_tools: true}}\ndefault_tier: plain\n"))
	if err != nil {
		t.Fatal(err)
	}
	// A policy that grants the tools needs a host that has them.
	if err := r.UsePolicy(p); err == nil || !strings.Contains(err.Error(), "the host has them turned off") {
		t.Fatalf("UsePolicy without the tools: %v", err)
	}
	r.UseTicketTools(tools, srv.URL, []string{"jira-api-token-of-ochell", ""})
	if err := r.UsePolicy(p); err != nil {
		t.Fatal(err)
	}

	tk := newTask()
	tk.Tier = "tools"
	res := r.Run(context.Background(), tk)
	if res.Err != nil {
		t.Fatalf("run failed: %v", res.Err)
	}
	logged, err := os.ReadFile(res.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	out := string(logged)
	for _, want := range []string{
		"tools for DEV-1\nRun context from the orchestrator:\n- " + toolsNote + "\n",
		"token: [redacted ORCH_TOOLS_TOKEN]\n",
		`ticket: 200 {"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"Ticket DEV-1 (jira): The title`,
		"What the ticket asks for.",
		`comment: 200 {"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"The comment was added to DEV-1.","type":"text"}],"isError":false}}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the run log lacks %q:\n%s", want, out)
		}
	}
	if res.Grants != "ticket_tools" {
		t.Errorf("grants = %q, want ticket_tools", res.Grants)
	}
	// The token does not reach the ticket either.
	if len(tr.comments) != 1 || tr.comments[0] != "DEV-1: my token is [redacted ORCH_TOOLS_TOKEN]" {
		t.Errorf("the ticket got %q", tr.comments)
	}

	// A run of a tier without the grant has neither the tools nor the
	// note; its template still renders.
	plain := newTask()
	plain.ID, plain.Tier = "t2", "plain"
	res = r.Run(context.Background(), plain)
	logged, _ = os.ReadFile(res.LogFile)
	if out := string(logged); res.Err != nil || res.Grants != "" || !strings.Contains(out, "twg for DEV-1\n") || !strings.Contains(out, "token: \n") || !strings.Contains(out, "ticket: ") || strings.Contains(out, "The title") {
		t.Errorf("a run without the grant: %v, grants %q\n%s", res.Err, res.Grants, out)
	}

	// A run that would hold one of ochell's own tracker secrets is not
	// started with the tools.
	r.cfg.Env["TWG_TOKEN"] = "jira-api-token-of-ochell"
	again := newTask()
	again.ID, again.Tier = "t3", "tools"
	res = r.Run(context.Background(), again)
	if res.Outcome != task.OutcomeNotStarted || res.Err == nil || !strings.Contains(res.Err.Error(), "TWG_TOKEN in the run's environment holds a secret with which ochell itself reaches a tracker") || strings.Contains(res.Err.Error(), "jira-api-token") {
		t.Errorf("a run with ochell's own token: %s, %v", res.Outcome, res.Err)
	}
	if _, err := os.Stat(filepath.Join(cfg.LogDir, "t3.log")); !os.IsNotExist(err) {
		t.Errorf("the refused run left a log: %v", err)
	}
}

// With the claude adapter the tools reach the agent through the tier's MCP
// configuration, so a tier with the tools needs one.
func TestTicketToolsNeedAnMCPConfigForClaude(t *testing.T) {
	cfg := agentCfg(t, "echo")
	cfg.Adapter, cfg.PromptVia = "claude", "stdin"
	r, err := New(cfg, logger(), testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	r.UseTicketTools(mcp.New("test", logger()), "http://127.0.0.1:1/mcp", nil)
	p, err := policy.Parse([]byte("tiers:\n  - {name: tools, grants: {ticket_tools: true}}\ndefault_tier: tools\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UsePolicy(p); err == nil || !strings.Contains(err.Error(), "no grants.mcp_config") {
		t.Errorf("UsePolicy = %v, want an error about grants.mcp_config", err)
	}
}

func TestWithNote(t *testing.T) {
	if got := withNote("", "a note"); got != "Run context from the orchestrator:\n- a note" {
		t.Errorf("an empty run context: %q", got)
	}
	earlier := runContext(&task.Task{Attempt: 2}, true)
	if got := withNote(earlier, "a note"); !strings.HasPrefix(got, "Run context from the orchestrator:\n- a note\n- This is attempt 2") {
		t.Errorf("a run context with a line: %q", got)
	}
}
