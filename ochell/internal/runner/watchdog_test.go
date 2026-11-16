package runner

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"ochell/internal/task"
)

// The watchdog fires when the last calls of a run are one circle that
// went round as often as it allows, and at nothing else.
func TestWatchdog(t *testing.T) {
	// Each letter is one tool call; the same letter is the same call.
	for name, c := range map[string]struct {
		repeats int
		calls   string
		// at is the number of the call that the watchdog fires at; 0:
		// it does not fire.
		at   int
		want string
	}{
		"the same call":                  {3, "AAAA", 3, "it made the same tool call 3 times in a row (tool A)"},
		"one short of it":                {3, "AABAAC", 0, ""},
		"after other work":               {3, "ABCDEEE", 7, "the same tool call 3 times in a row (tool E)"},
		"twice is the lowest":            {2, "ABB", 3, "the same tool call 2 times in a row (tool B)"},
		"a circle of two":                {3, "ABABAB", 6, "it made the same 2 tool calls, in the same order, 3 times in a row (tool A, tool B)"},
		"a circle of two, begun midway":  {3, "XBABABA", 7, "the same 2 tool calls, in the same order, 3 times in a row (tool B, tool A)"},
		"a circle of two, cut short":     {3, "ABABA", 0, ""},
		"a circle of two that is broken": {3, "ABABCABAB", 0, ""},
		"a circle of three":              {2, "ABCABC", 6, "the same 3 tool calls, in the same order, 2 times in a row (tool A, tool B, tool C)"},
		"a circle of four is not seen":   {2, "ABCDABCDABCD", 0, ""},
		"varied work":                    {2, "ABCDEFGACEBDF", 0, ""},
		"off":                            {0, "AAAAAAAAAA", 0, ""},
	} {
		w := newWatchdog(c.repeats)
		at := 0
		for i, r := range c.calls {
			w.observe(toolCall{id: string(r), tool: "tool", param: string(r)})
			select {
			case <-w.stopped():
				if at == 0 {
					at = i + 1
				}
			default:
			}
		}
		if at != c.at || !strings.Contains(w.reason(), c.want) || (c.at == 0) != (w.reason() == "") {
			t.Errorf("%s: fired at call %d with %q; want at %d with %q", name, at, w.reason(), c.at, c.want)
		}
	}
	// What people are shown of a call does not make two calls the same:
	// the same program with other arguments each time is work.
	w := newWatchdog(2)
	for _, id := range []string{"1", "2", "3", "4", "5", "6"} {
		w.observe(toolCall{id: id, tool: "Bash", param: "git"})
	}
	if w.reason() != "" {
		t.Errorf("six different calls of one tool: %q", w.reason())
	}
	// A call that nothing identifies is not counted, and a tool without a
	// parameter is named alone.
	w = newWatchdog(2)
	w.observe(toolCall{tool: "Read"})
	w.observe(toolCall{tool: "Read"})
	if w.reason() != "" {
		t.Errorf("calls without an id: %q", w.reason())
	}
	w.observe(toolCall{id: "x", tool: "Task"})
	w.observe(toolCall{id: "x", tool: "Task"})
	if got := w.reason(); got != "it made the same tool call 2 times in a row (Task)" {
		t.Errorf("reason = %q", got)
	}
}

// A run that makes the same tool call again and again is stopped as
// no_progress, and says what was seen without the call's input. One that
// stays below the limit, and one whose adapter reports no tool calls, run
// to their end.
func TestWatchdogStopsTheRun(t *testing.T) {
	claude := func(mode string, repeats int) *Runner {
		cfg := agentCfg(t, mode)
		cfg.Adapter, cfg.PromptVia = "claude", "stdin"
		cfg.Watchdog.Repeats = repeats
		r, err := New(cfg, logger(), testStore(t))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	start := time.Now()
	res := claude("loop", 5).Run(context.Background(), newTask())
	if res.Outcome != task.OutcomeNoProgress || res.Err == nil ||
		res.Err.Error() != "the agent made no progress and was stopped: it made the same tool call 5 times in a row (Bash gh)" {
		t.Errorf("a run in a circle: %+v, want no_progress", res)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("the run was stopped after %s", d)
	}
	if res.SessionID != "sess-loop" {
		t.Errorf("session = %q: the session of the stopped run is not kept", res.SessionID)
	}
	logged, _ := os.ReadFile(res.LogFile)
	if !strings.Contains(string(logged), "outcome=no_progress") {
		t.Errorf("the log does not say why the run ended:\n%s", logged)
	}

	// The limit is higher than what the agent does.
	if res := claude("loop", 50).Run(context.Background(), newTask()); res.Outcome != task.OutcomeFinished {
		t.Errorf("a run below the limit: %+v, want finished", res)
	}
	// Off: the default.
	if res := claude("loop", 0).Run(context.Background(), newTask()); res.Outcome != task.OutcomeFinished {
		t.Errorf("a run without the watchdog: %+v, want finished", res)
	}
	// The plain adapter reports no tool calls: the watchdog sees nothing.
	cfg := agentCfg(t, "loop")
	cfg.Watchdog.Repeats = 2
	r, _ := New(cfg, logger(), testStore(t))
	if res := r.Run(context.Background(), newTask()); res.Outcome != task.OutcomeFinished {
		t.Errorf("a run with the plain adapter: %+v, want finished", res)
	}
}

// A run that the watchdog stopped is not started again by ochell.
func TestNoRetryAfterTheWatchdog(t *testing.T) {
	cfg := agentCfg(t, "echo")
	cfg.MaxAttempts = 5
	r, _ := New(cfg, logger(), testStore(t))
	if again, ok := r.next(&task.Task{Source: "jira", Key: "DEV-1", Attempt: 1}, task.Result{Outcome: task.OutcomeNoProgress, Message: "rate limit"}); ok {
		t.Errorf("next = %+v, want no run", again)
	}
}
