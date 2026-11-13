package runner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	case "env":
		for _, kv := range os.Environ() {
			fmt.Println("env:", kv)
		}
	case "stdin":
		b, _ := io.ReadAll(os.Stdin)
		fmt.Print("stdin:", string(b))
	case "sleep":
		time.Sleep(10 * time.Second)
	case "nap":
		time.Sleep(300 * time.Millisecond)
		fmt.Println("rested")
	case "fail":
		fmt.Println("boom")
		os.Exit(3)
	}
	os.Exit(0)
}

func agentCfg(t *testing.T, mode string, extraArgs ...string) config.Agent {
	dir := t.TempDir()
	return config.Agent{
		Command:        os.Args[0],
		Args:           append([]string{"-test.run=TestHelperAgent", "--", mode}, extraArgs...),
		PromptVia:      "arg",
		PromptTemplate: "Fix {{.Key}}: {{.Title}}",
		Workdir:        filepath.Join(dir, "work", "{{.Key}}"),
		EnvPass:        config.DefaultEnvPass,
		Env:            map[string]string{"ORCH_HELPER": "1"},
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

func TestRunEnvironmentIsAllowlisted(t *testing.T) {
	// What ochell typically has in its own environment.
	secrets := map[string]string{
		"JIRA_WEBHOOK_SECRET":  "jira-secret-value",
		"LINEAR_CLIENT_SECRET": "linear-secret-value",
		"NGROK_API_KEY":        "ngrok-secret-value",
		"ORCH_INHERITED":       "orch-secret-value",
	}
	for k, v := range secrets {
		t.Setenv(k, v)
	}
	t.Setenv("LANG", "en_AU.UTF-8")
	t.Setenv("OCHELL_TEST_PASSED", "passed-on")
	cfg := agentCfg(t, "env")
	cfg.EnvPass = append([]string{"OCHELL_TEST_PASSED", "OCHELL_TEST_UNSET"}, cfg.EnvPass...)
	cfg.Env["AGENT_SETTING"] = "from-config"
	r, err := New(cfg, logger())
	if err != nil {
		t.Fatal(err)
	}
	res := r.Run(context.Background(), newTask())
	if res.Err != nil {
		t.Fatalf("run failed: %v\n%s", res.Err, res.Tail)
	}
	logged, err := os.ReadFile(res.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	out := string(logged)
	for k, v := range secrets {
		if strings.Contains(out, k) || strings.Contains(out, v) {
			t.Errorf("agent environment leaks %s", k)
		}
	}
	for _, want := range []string{
		"env: PATH=" + os.Getenv("PATH"), "env: LANG=en_AU.UTF-8", "env: OCHELL_TEST_PASSED=passed-on",
		"env: ORCH_TASK_KEY=DEV-1", "env: ORCH_TASK_ID=t1", "env: AGENT_SETTING=from-config",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("agent environment missing %q", want)
		}
	}
	if strings.Contains(out, "OCHELL_TEST_UNSET") {
		t.Error("a variable that is not set must not be passed as empty")
	}
}

func TestRunOutcomes(t *testing.T) {
	r, _ := New(agentCfg(t, "echo"), logger())
	if res := r.Run(context.Background(), newTask()); res.Outcome != task.OutcomeFinished || res.Err != nil || res.ExitCode != 0 {
		t.Errorf("finished run: %+v", res)
	}

	r, _ = New(agentCfg(t, "fail"), logger())
	if res := r.Run(context.Background(), newTask()); res.Outcome != task.OutcomeFailed || res.Err == nil || res.ExitCode != 3 {
		t.Errorf("failed run: outcome %s exit %d err %v", res.Outcome, res.ExitCode, res.Err)
	}

	cfg := agentCfg(t, "sleep")
	cfg.Timeout = 200 * time.Millisecond
	r, _ = New(cfg, logger())
	res := r.Run(context.Background(), newTask())
	if res.Outcome != task.OutcomeTimedOut || res.Err == nil || !strings.Contains(res.Err.Error(), "timed out") {
		t.Errorf("timed out run: outcome %s err %v", res.Outcome, res.Err)
	}
	if res.Duration > 5*time.Second {
		t.Errorf("the agent was not stopped at the time limit: %s", res.Duration)
	}

	// A run that ochell stops is reported as stopped, whatever the exit code.
	r, _ = New(agentCfg(t, "sleep"), logger())
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	res = r.Run(ctx, newTask())
	if res.Outcome != task.OutcomeStopped || res.Err == nil {
		t.Errorf("stopped run: outcome %s err %v", res.Outcome, res.Err)
	}
	logged, _ := os.ReadFile(res.LogFile)
	if !strings.Contains(string(logged), "outcome=stopped") {
		t.Errorf("the log does not say why the run ended:\n%s", logged)
	}

	cfg = agentCfg(t, "echo")
	cfg.Command = filepath.Join(t.TempDir(), "no-such-agent")
	r, _ = New(cfg, logger())
	if res := r.Run(context.Background(), newTask()); res.Outcome != task.OutcomeNotStarted || res.Err == nil || res.ExitCode != -1 {
		t.Errorf("agent that cannot start: outcome %s exit %d err %v", res.Outcome, res.ExitCode, res.Err)
	}
}

// With the systemd launcher, ticket text must not be able to reach the
// command line.
func TestSystemdLauncherRefusesTicketTextInArguments(t *testing.T) {
	for _, field := range []string{".Title", ".URL", ".Context", ".Prompt", ".DeliveryID"} {
		cfg := agentCfg(t, "echo", "--name={{"+field+"}}")
		cfg.Launcher = "systemd"
		if _, err := New(cfg, logger()); err == nil || !strings.Contains(err.Error(), "only .ID, .Source and .Key") {
			t.Errorf("{{%s}} in an argument: got %v", field, err)
		}
	}
	cfg := agentCfg(t, "echo", "--session={{.Source}}-{{.Key}}-{{.ID}}")
	cfg.Launcher = "systemd"
	if _, err := New(cfg, logger()); err != nil {
		t.Errorf(".ID, .Source and .Key must be allowed: %v", err)
	}
	cfg = agentCfg(t, "echo")
	cfg.Launcher = "systemd"
	cfg.Workdir = "/work/{{.Title}}"
	if _, err := New(cfg, logger()); err == nil {
		t.Error("{{.Title}} in workdir must be refused")
	}
	// The direct launcher keeps the old behaviour.
	if _, err := New(agentCfg(t, "echo", "{{.Title}}"), logger()); err != nil {
		t.Errorf("direct launcher: %v", err)
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
	r.Start()
	select {
	case res := <-done:
		if res.Err != nil {
			t.Fatalf("task failed: %v", res.Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("task did not finish")
	}
	r.Shutdown(context.Background())
	if err := r.Submit(newTask()); err != ErrStopped {
		t.Fatalf("submit after shutdown: got %v", err)
	}
}

// finished collects the result of each task by ticket key.
type finished struct {
	mu  sync.Mutex
	res map[string]task.Result
}

func (f *finished) task(key string) *task.Task {
	tk := newTask()
	tk.ID, tk.Key = "t-"+key, key
	tk.OnFinish = func(_ context.Context, t *task.Task, res task.Result) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.res == nil {
			f.res = map[string]task.Result{}
		}
		f.res[t.Key] = res
		return nil
	}
	return tk
}

func (f *finished) outcome(key string) task.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.res[key].Outcome
}

func waitRunning(t *testing.T, r *Runner, logDir, id string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(logDir, id+".log")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s did not start", id)
		}
	}
}

// A shutdown waits for the running agent, and starts nothing new.
func TestShutdownDrains(t *testing.T) {
	cfg := agentCfg(t, "nap")
	r, _ := New(cfg, logger())
	var f finished
	for _, key := range []string{"A-1", "A-2"} {
		if err := r.Submit(f.task(key)); err != nil {
			t.Fatal(err)
		}
	}
	r.Start()
	waitRunning(t, r, cfg.LogDir, "t-A-1")
	r.Shutdown(context.Background())
	if got := f.outcome("A-1"); got != task.OutcomeFinished {
		t.Errorf("running task: outcome %q, want finished: the shutdown must wait for it", got)
	}
	if got := f.outcome("A-2"); got != task.OutcomeNotStarted {
		t.Errorf("queued task: outcome %q, want not_started", got)
	}
	if n := r.Running(); n != 0 {
		t.Errorf("Running() = %d after shutdown, want 0", n)
	}
}

// When the wait is over, the running agent is stopped.
func TestShutdownStopsAfterTheWait(t *testing.T) {
	cfg := agentCfg(t, "sleep")
	cfg.Timeout = time.Minute
	r, _ := New(cfg, logger())
	var f finished
	if err := r.Submit(f.task("B-1")); err != nil {
		t.Fatal(err)
	}
	r.Start()
	waitRunning(t, r, cfg.LogDir, "t-B-1")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	r.Shutdown(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("shutdown took %s; the agent was not stopped", d)
	}
	if got := f.outcome("B-1"); got != task.OutcomeStopped {
		t.Errorf("outcome %q, want stopped", got)
	}
}

func TestBadTemplate(t *testing.T) {
	cfg := agentCfg(t, "echo", "{{.Nope")
	if _, err := New(cfg, logger()); err == nil {
		t.Fatal("expected template parse error")
	}
}
