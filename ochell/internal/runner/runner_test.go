package runner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ochell/internal/config"
	"ochell/internal/task"
)

// TestHelperAgent is executed as the fake agent CLI by the tests below.
func TestHelperAgent(t *testing.T) {
	if os.Getenv("ORCH_HELPER") != "1" {
		t.Skip("helper process")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	switch args[0] {
	case "echo":
		fmt.Println("args:", strings.Join(args[1:], "|"))
		fmt.Println("key:", os.Getenv("ORCH_TASK_KEY"))
		wd, _ := os.Getwd()
		fmt.Println("wd:", filepath.Base(wd))
	case "stdin":
		b, _ := io.ReadAll(os.Stdin)
		fmt.Print("stdin:", string(b))
	case "sleep":
		time.Sleep(10 * time.Second)
	case "fail":
		fmt.Println("boom")
		os.Exit(3)
	}
	os.Exit(0)
}

func agentCfg(t *testing.T, mode string, extraArgs ...string) config.Agent {
	t.Setenv("ORCH_HELPER", "1")
	dir := t.TempDir()
	return config.Agent{
		Command:        os.Args[0],
		Args:           append([]string{"-test.run=TestHelperAgent", "--", mode}, extraArgs...),
		PromptVia:      "arg",
		PromptTemplate: "Fix {{.Key}}: {{.Title}}",
		Workdir:        filepath.Join(dir, "work", "{{.Key}}"),
		Timeout:        5 * time.Second,
		MaxConcurrent:  1,
		QueueSize:      2,
		LogDir:         filepath.Join(dir, "logs"),
	}
}

func newTask() *task.Task {
	return &task.Task{ID: "t1", Source: "jira", Key: "DEV-1", Title: "it's \"quoted\"; rm -rf /"}
}

func logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRunArgsAreNotShellInterpreted(t *testing.T) {
	r, err := New(agentCfg(t, "echo", "{{.Prompt}}"), logger())
	if err != nil {
		t.Fatal(err)
	}
	res := r.Run(context.Background(), newTask())
	if res.Err != nil {
		t.Fatalf("run failed: %v\n%s", res.Err, res.Tail)
	}
	for _, want := range []string{`args: Fix DEV-1: it's "quoted"; rm -rf /`, "key: DEV-1", "wd: DEV-1"} {
		if !strings.Contains(res.Tail, want) {
			t.Errorf("output missing %q:\n%s", want, res.Tail)
		}
	}
	logged, _ := os.ReadFile(res.LogFile)
	if !strings.Contains(string(logged), "exit=0") {
		t.Errorf("log file incomplete:\n%s", logged)
	}
}

func TestRunStdin(t *testing.T) {
	cfg := agentCfg(t, "stdin")
	cfg.PromptVia = "stdin"
	r, _ := New(cfg, logger())
	res := r.Run(context.Background(), newTask())
	if res.Err != nil || !strings.Contains(res.Tail, "stdin:Fix DEV-1") {
		t.Fatalf("err=%v tail=%q", res.Err, res.Tail)
	}
}

func TestRunFailureAndTimeout(t *testing.T) {
	r, _ := New(agentCfg(t, "fail"), logger())
	if res := r.Run(context.Background(), newTask()); res.Err == nil || res.ExitCode != 3 {
		t.Errorf("expected exit 3, got %d %v", res.ExitCode, res.Err)
	}
	cfg := agentCfg(t, "sleep")
	cfg.Timeout = 200 * time.Millisecond
	r, _ = New(cfg, logger())
	res := r.Run(context.Background(), newTask())
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timed out") {
		t.Errorf("expected timeout, got %v", res.Err)
	}
}

func TestSubmitInFlightAndCallbacks(t *testing.T) {
	r, _ := New(agentCfg(t, "echo"), logger())
	done := make(chan task.Result, 1)
	tk := newTask()
	tk.OnFinish = func(_ context.Context, _ *task.Task, res task.Result) error {
		done <- res
		return nil
	}
	if err := r.Submit(tk); err != nil {
		t.Fatal(err)
	}
	if err := r.Submit(newTask()); err != ErrBusy {
		t.Fatalf("second submit for same ticket: got %v, want ErrBusy", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	select {
	case res := <-done:
		if res.Err != nil {
			t.Fatalf("task failed: %v", res.Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("task did not finish")
	}
	cancel()
	r.Stop()
	if err := r.Submit(newTask()); err != ErrStopped {
		t.Fatalf("submit after stop: got %v", err)
	}
}

func TestBadTemplate(t *testing.T) {
	cfg := agentCfg(t, "echo", "{{.Nope")
	if _, err := New(cfg, logger()); err == nil {
		t.Fatal("expected template parse error")
	}
}
