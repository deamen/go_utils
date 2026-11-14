package agent

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"ochell/internal/config"
)

func TestClaudeCommand(t *testing.T) {
	run := Run{Args: []string{"-p", "--permission-mode", "acceptEdits"}, Prompt: "Fix ENG-123"}
	cmd, err := Claude{}.Start(run)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cmd.Args, " "); got != "-p --permission-mode acceptEdits --output-format stream-json --verbose" {
		t.Errorf("start arguments = %q", got)
	}
	if stdin, _ := io.ReadAll(cmd.Stdin); string(stdin) != "Fix ENG-123" {
		t.Errorf("stdin = %q, want the prompt", stdin)
	}
	if len(run.Args) != 3 {
		t.Errorf("Start changed the caller's arguments: %q", run.Args)
	}

	// -p is added when the configured arguments leave it out.
	cmd, _ = Claude{}.Start(Run{Args: []string{"--model", "x"}})
	if got := strings.Join(cmd.Args, " "); got != "--model x -p --output-format stream-json --verbose" {
		t.Errorf("start arguments without -p = %q", got)
	}

	cmd, err = Claude{}.Resume(run, "3dc26999-bd50-487b-b445-cb41a233c6a2")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cmd.Args, " "); got != "-p --permission-mode acceptEdits --output-format stream-json --verbose --resume 3dc26999-bd50-487b-b445-cb41a233c6a2" {
		t.Errorf("resume arguments = %q", got)
	}
	if stdin, _ := io.ReadAll(cmd.Stdin); string(stdin) != "Fix ENG-123" {
		t.Errorf("stdin of a resumed run = %q, want the prompt", stdin)
	}
	// The session id goes into an argument: nothing that systemd or a
	// command line could read as something else.
	for _, bad := range []string{"", "${CLAUDE_CODE_OAUTH_TOKEN}", "--bare", "a b", "x;y"} {
		if _, err := (Claude{}).Resume(run, bad); !errors.Is(err, ErrNoResume) {
			t.Errorf("Resume(%q) = %v, want ErrNoResume", bad, err)
		}
	}
}

func TestClaudeAdapterSettings(t *testing.T) {
	ok := config.Agent{Adapter: "claude", PromptVia: "stdin", Args: []string{"-p", "--permission-mode", "acceptEdits"}}
	if a, err := New(ok); err != nil {
		t.Fatal(err)
	} else if _, isClaude := a.(Claude); !isClaude {
		t.Fatalf("adapter = %#v", a)
	}
	cfg := ok
	cfg.PromptVia = "arg"
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "prompt_via: stdin") {
		t.Errorf("prompt_via arg: %v", err)
	}
	for _, arg := range []string{"--output-format", "--output-format=json", "--resume", "-r", "--continue", "-c", "--bare"} {
		cfg := ok
		cfg.Args = []string{"-p", arg}
		if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), strings.SplitN(arg, "=", 2)[0]) {
			t.Errorf("argument %s: %v, want it refused", arg, err)
		}
	}
}

// The sample is the output of Claude Code 2.1.311, shortened: stderr and
// stdout mixed, with event types and fields that ochell does not use.
func TestClaudeOutput(t *testing.T) {
	raw, err := os.ReadFile("testdata/claude-stream.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	want := Report{
		Message:   "Opened PR #7 for ENG-123.",
		SessionID: "3dc26999-bd50-487b-b445-cb41a233c6a2",
		CostUSD:   0.09006600000000001,
		Usage:     Usage{InputTokens: 2, OutputTokens: 4, CacheReadTokens: 11852, CacheWriteTokens: 8403},
	}
	// However the stream is cut into writes, the report is the same.
	for _, chunk := range []int{len(raw), 1, 7, 4096} {
		out := Claude{}.Output(nil)
		for rest := raw; len(rest) > 0; {
			n := min(chunk, len(rest))
			out.Write(rest[:n])
			rest = rest[n:]
		}
		if got := out.Report(); got != want {
			t.Errorf("written %d bytes at a time:\n got %+v\nwant %+v", chunk, got, want)
		}
	}
}

func TestClaudeOutputWithoutResult(t *testing.T) {
	// Stopped in the middle: the session is known, the message is the last
	// thing the agent said.
	out := Claude{}.Output(nil)
	io.WriteString(out, `{"type":"system","subtype":"init","session_id":"sess-1"}`+"\n")
	io.WriteString(out, `{"type":"assistant","message":{"content":[{"type":"text","text":"Working on it."}]},"session_id":"sess-1"}`+"\n")
	io.WriteString(out, `{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash"}]},"session_id":"sess-1"}`)
	if got := out.Report(); got.SessionID != "sess-1" || got.Message != "Working on it." || got.CostUSD != 0 {
		t.Errorf("stopped run: %+v", got)
	}

	// Claude Code could not start a session: what it printed is the message.
	out = Claude{}.Output(nil)
	io.WriteString(out, "No conversation found with session ID: sess-9\n")
	if got := out.Report(); got.SessionID != "" || got.Message != "No conversation found with session ID: sess-9" {
		t.Errorf("failed start: %+v", got)
	}

	// An error result: its text is the message.
	out = Claude{}.Output(nil)
	io.WriteString(out, `{"type":"result","subtype":"error_max_turns","is_error":true,"result":"","session_id":"sess-2","total_cost_usd":1.5}`+"\n")
	io.WriteString(out, "Error: reached the turn limit\n")
	if got := out.Report(); got.SessionID != "sess-2" || got.CostUSD != 1.5 || got.Message != "Error: reached the turn limit" {
		t.Errorf("error result: %+v", got)
	}

	// A session id that is not one is not taken over.
	out = Claude{}.Output(nil)
	io.WriteString(out, `{"type":"system","subtype":"init","session_id":"${HOME}"}`+"\n")
	if got := out.Report(); got.SessionID != "" {
		t.Errorf("session id %q was accepted", got.SessionID)
	}
}

func TestClaudeOutputSkipsHugeLines(t *testing.T) {
	out := Claude{}.Output(nil)
	io.WriteString(out, `{"type":"system","subtype":"init","session_id":"sess-1"}`+"\n")
	big := strings.Repeat("x", 1<<20)
	io.WriteString(out, `{"type":"user","message":"`)
	for range maxLine/len(big) + 1 {
		io.WriteString(out, big)
	}
	io.WriteString(out, `"}`+"\n")
	io.WriteString(out, `{"type":"result","result":"done","session_id":"sess-1"}`+"\n")
	if got := out.Report(); got.Message != "done" || got.SessionID != "sess-1" {
		t.Errorf("after a line over the limit: message %.40q session %q", got.Message, got.SessionID)
	}
	if o := out.(*claudeOutput); cap(o.line) > maxLine {
		t.Errorf("the line buffer grew to %d bytes", cap(o.line))
	}
}
