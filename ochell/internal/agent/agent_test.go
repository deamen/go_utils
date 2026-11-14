package agent

import (
	"errors"
	"io"
	"strings"
	"testing"

	"ochell/internal/config"
)

func TestNew(t *testing.T) {
	for _, name := range []string{"", "plain"} {
		a, err := New(config.Agent{Adapter: name, PromptVia: "stdin"})
		if err != nil {
			t.Fatalf("adapter %q: %v", name, err)
		}
		if p, ok := a.(Plain); !ok || !p.PromptOnStdin {
			t.Errorf("adapter %q = %#v, want the plain adapter with the prompt on stdin", name, a)
		}
	}
	if _, err := New(config.Agent{Adapter: "telepathy"}); err == nil {
		t.Error("an unknown adapter must be refused")
	}
}

func TestPlainCommand(t *testing.T) {
	run := Run{Args: []string{"-p", "--model", "x"}, Prompt: "Fix DEV-1"}

	cmd, err := Plain{PromptOnStdin: true}.Start(run)
	if err != nil {
		t.Fatal(err)
	}
	stdin, _ := io.ReadAll(cmd.Stdin)
	if strings.Join(cmd.Args, " ") != "-p --model x" || string(stdin) != "Fix DEV-1" {
		t.Errorf("stdin mode: args %q, stdin %q", cmd.Args, stdin)
	}

	// prompt_via: arg. The configured arguments already hold the prompt.
	cmd, err = Plain{}.Start(run)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Stdin != nil || strings.Join(cmd.Args, " ") != "-p --model x" {
		t.Errorf("arg mode: args %q, stdin %v", cmd.Args, cmd.Stdin)
	}

	if _, err := (Plain{}).Resume(run, "session-1"); !errors.Is(err, ErrNoResume) {
		t.Errorf("Resume = %v, want ErrNoResume", err)
	}
}

func TestPlainOutputKeepsTheTail(t *testing.T) {
	out := Plain{}.Output(nil)
	if got := out.Report(); got != (Report{}) {
		t.Errorf("report of a silent run = %+v", got)
	}
	out.Write([]byte(strings.Repeat("x", tailSize)))
	out.Write([]byte("the last words"))
	rep := out.Report()
	if len(rep.Message) != tailSize || !strings.HasSuffix(rep.Message, "xthe last words") {
		t.Errorf("message has %d bytes and ends with %q", len(rep.Message), rep.Message[len(rep.Message)-20:])
	}
	if rep.SessionID != "" || rep.CostUSD != 0 {
		t.Errorf("the plain adapter knows no session and no cost: %+v", rep)
	}
}
