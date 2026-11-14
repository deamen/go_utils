package agent

import (
	"bytes"
	"strings"
	"sync"
)

// tailSize is how much of the output the plain adapter keeps as the message.
const tailSize = 4096

// Plain works with any CLI: the prompt goes in, and the last part of the
// output is the result. It knows no sessions and no cost.
type Plain struct {
	// PromptOnStdin writes the prompt to the agent's stdin. Otherwise the
	// configured arguments carry it ({{.Prompt}}, prompt_via: arg).
	PromptOnStdin bool
}

func (p Plain) Start(run Run) (Command, error) {
	cmd := Command{Args: run.Args}
	if p.PromptOnStdin {
		cmd.Stdin = strings.NewReader(run.Prompt)
	}
	return cmd, nil
}

func (Plain) Resume(Run, string) (Command, error) { return Command{}, ErrNoResume }

func (Plain) Output(func(Event)) Output { return &tail{max: tailSize} }

// tail keeps the last max bytes written to it.
type tail struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Write(p)
	if over := t.buf.Len() - t.max; over > 0 {
		t.buf.Next(over)
	}
	return len(p), nil
}

func (t *tail) Report() Report {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Report{Message: t.buf.String()}
}
