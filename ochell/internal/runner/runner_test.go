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

	"ochell/internal/agent"
	"ochell/internal/config"
	"ochell/internal/store"
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
	case "chatty":
		// Works for a second, and says something all along.
		for range 10 {
			fmt.Println("still working")
			time.Sleep(100 * time.Millisecond)
		}
	case "nap":
		time.Sleep(300 * time.Millisecond)
		fmt.Println("rested")
	case "fail":
		fmt.Println("boom")
		os.Exit(3)
	case "mark":
		// Notes that it ran, in order, for the workspace hook tests.
		wd, _ := os.Getwd()
		f, err := os.OpenFile(os.Getenv("ORCH_TEST_MARKS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Println(err)
			os.Exit(5)
		}
		fmt.Fprintf(f, "%s in %s branch=%s hook=%s\n", args[1], filepath.Base(wd), os.Getenv("ORCH_TASK_BRANCH"), os.Getenv("ORCH_HOOK"))
		f.Close()
		if len(args) > 2 && args[2] == "fail" {
			os.Exit(4)
		}
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
		RunDir:         filepath.Join(dir, "runs"),
	}
}

func newTask() *task.Task {
	return &task.Task{ID: "t1", Source: "jira", Key: "DEV-1", Title: "it's \"quoted\"; rm -rf /"}
}

func logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	return openStore(t, filepath.Join(t.TempDir(), "ochell.db"))
}

func TestRunArgsAreNotShellInterpreted(t *testing.T) {
	r, err := New(agentCfg(t, "echo", "{{.Prompt}}"), logger(), testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	res := r.Run(context.Background(), newTask())
	if res.Err != nil {
		t.Fatalf("run failed: %v\n%s", res.Err, res.Message)
	}
	for _, want := range []string{`args: Fix DEV-1: it's "quoted"; rm -rf /`, "key: DEV-1", "wd: DEV-1"} {
		if !strings.Contains(res.Message, want) {
			t.Errorf("output missing %q:\n%s", want, res.Message)
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
	r, _ := New(cfg, logger(), testStore(t))
	res := r.Run(context.Background(), newTask())
	if res.Err != nil || !strings.Contains(res.Message, "stdin:Fix DEV-1") {
		t.Fatalf("err=%v message=%q", res.Err, res.Message)
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
	r, err := New(cfg, logger(), testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	res := r.Run(context.Background(), newTask())
	if res.Err != nil {
		t.Fatalf("run failed: %v\n%s", res.Err, res.Message)
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

// fakeAdapter changes the command and the result, to show that the runner
// takes both from the adapter.
type fakeAdapter struct{}

func (fakeAdapter) Start(run agent.Run) (agent.Command, error) {
	return agent.Command{Args: append(run.Args, "--from-adapter"), Stdin: strings.NewReader("adapter stdin: " + run.Prompt)}, nil
}
func (fakeAdapter) Resume(run agent.Run, session string) (agent.Command, error) {
	return agent.Command{Args: append(run.Args, "--resume", session)}, nil
}
func (fakeAdapter) Output(func(agent.Event)) agent.Output { return &fakeOutput{} }

type fakeOutput struct{ n int }

func (o *fakeOutput) Write(p []byte) (int, error) { o.n += len(p); return len(p), nil }
func (o *fakeOutput) Report() agent.Report {
	return agent.Report{Message: fmt.Sprintf("the adapter read %d bytes", o.n), SessionID: "sess-1", CostUSD: 0.5}
}

// The second run of a ticket resumes the session of the first, when it runs
// in the same working directory.
func TestSecondRunResumesTheSession(t *testing.T) {
	second := func(t *testing.T, cfg config.Agent) (first, again *store.Run, log string) {
		st := testStore(t)
		r, err := New(cfg, logger(), st)
		if err != nil {
			t.Fatal(err)
		}
		r.adapter = fakeAdapter{}
		f := &finished{done: make(chan string, 2)}
		r.SetNotifier(f)
		if err := r.Start(); err != nil {
			t.Fatal(err)
		}
		defer r.Shutdown(context.Background())
		for _, id := range []string{"t1", "t2"} {
			tk := newTask()
			tk.ID = id
			if err := r.Submit(tk); err != nil {
				t.Fatal(err)
			}
			f.wait(t, "DEV-1")
		}
		first, _ = st.Run("t1")
		again, _ = st.Run("t2")
		raw, _ := os.ReadFile(again.Result.LogFile)
		return first, again, string(raw)
	}

	first, again, log := second(t, agentCfg(t, "echo"))
	if first.Result.Resumed || first.Result.SessionID != "sess-1" || first.Result.CostUSD != 0.5 {
		t.Errorf("first run = %+v, want a new session sess-1 and its cost", first.Result)
	}
	if !again.Result.Resumed || !strings.Contains(log, "args: --resume|sess-1") || !strings.Contains(log, "session=resumed sess-1") {
		t.Errorf("second run: resumed = %v, log:\n%s", again.Result.Resumed, log)
	}

	// In another working directory the session's files are not there.
	cfg := agentCfg(t, "echo")
	cfg.Workdir = filepath.Join(t.TempDir(), "{{.ID}}")
	_, again, log = second(t, cfg)
	if again.Result.Resumed || strings.Contains(log, "--resume") || !strings.Contains(log, "session=new") {
		t.Errorf("second run in another directory: resumed = %v, log:\n%s", again.Result.Resumed, log)
	}
}

func TestRunGoesThroughTheAdapter(t *testing.T) {
	r, err := New(agentCfg(t, "stdin"), logger(), testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	r.adapter = fakeAdapter{}
	res := r.Run(context.Background(), newTask())
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	logged, _ := os.ReadFile(res.LogFile)
	if !strings.Contains(string(logged), "stdin:adapter stdin: Fix DEV-1") {
		t.Errorf("the agent did not get the stdin the adapter built:\n%s", logged)
	}
	if !strings.HasPrefix(res.Message, "the adapter read ") || res.Message == "the adapter read 0 bytes" {
		t.Errorf("message = %q, want what the adapter reported", res.Message)
	}

	r, _ = New(agentCfg(t, "echo"), logger(), testStore(t))
	r.adapter = fakeAdapter{}
	res = r.Run(context.Background(), newTask())
	logged, _ = os.ReadFile(res.LogFile)
	if !strings.Contains(string(logged), "args: --from-adapter") {
		t.Errorf("the agent did not get the arguments the adapter built:\n%s", logged)
	}
}

func TestRunOutcomes(t *testing.T) {
	r, _ := New(agentCfg(t, "echo"), logger(), testStore(t))
	if res := r.Run(context.Background(), newTask()); res.Outcome != task.OutcomeFinished || res.Err != nil || res.ExitCode != 0 {
		t.Errorf("finished run: %+v", res)
	}

	r, _ = New(agentCfg(t, "fail"), logger(), testStore(t))
	if res := r.Run(context.Background(), newTask()); res.Outcome != task.OutcomeFailed || res.Err == nil || res.ExitCode != 3 {
		t.Errorf("failed run: outcome %s exit %d err %v", res.Outcome, res.ExitCode, res.Err)
	}

	cfg := agentCfg(t, "sleep")
	cfg.Timeout = 200 * time.Millisecond
	r, _ = New(cfg, logger(), testStore(t))
	res := r.Run(context.Background(), newTask())
	if res.Outcome != task.OutcomeTimedOut || res.Err == nil || !strings.Contains(res.Err.Error(), "timed out") {
		t.Errorf("timed out run: outcome %s err %v", res.Outcome, res.Err)
	}
	if res.Duration > 5*time.Second {
		t.Errorf("the agent was not stopped at the time limit: %s", res.Duration)
	}

	// A run that ochell stops is reported as stopped, whatever the exit code.
	r, _ = New(agentCfg(t, "sleep"), logger(), testStore(t))
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
	r, _ = New(cfg, logger(), testStore(t))
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
		if _, err := New(cfg, logger(), testStore(t)); err == nil || !strings.Contains(err.Error(), "only .ID, .Source and .Key") {
			t.Errorf("{{%s}} in an argument: got %v", field, err)
		}
	}
	cfg := agentCfg(t, "echo", "--session={{.Source}}-{{.Key}}-{{.ID}}")
	cfg.Launcher = "systemd"
	if _, err := New(cfg, logger(), testStore(t)); err != nil {
		t.Errorf(".ID, .Source and .Key must be allowed: %v", err)
	}
	cfg = agentCfg(t, "echo")
	cfg.Launcher = "systemd"
	cfg.Workdir = "/work/{{.Title}}"
	if _, err := New(cfg, logger(), testStore(t)); err == nil {
		t.Error("{{.Title}} in workdir must be refused")
	}
	// The direct launcher keeps the old behaviour.
	if _, err := New(agentCfg(t, "echo", "{{.Title}}"), logger(), testStore(t)); err != nil {
		t.Errorf("direct launcher: %v", err)
	}
}

func TestSubmitBusyAndNotifications(t *testing.T) {
	r, _ := New(agentCfg(t, "echo"), logger(), testStore(t))
	f := &finished{done: make(chan string, 4)}
	r.SetNotifier(f)
	if err := r.Submit(newTask()); err != nil {
		t.Fatal(err)
	}
	if err := r.Submit(newTask()); err != ErrBusy {
		t.Fatalf("second submit for same ticket: got %v, want ErrBusy", err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	f.wait(t, "DEV-1")
	if res := f.result("DEV-1"); res.Err != nil {
		t.Fatalf("task failed: %v", res.Err)
	}
	if got := f.attempt("DEV-1"); got != 1 {
		t.Errorf("the task was started as attempt %d, want 1", got)
	}
	// The ticket is free again, and its next run is the second attempt.
	tk := newTask()
	tk.ID = "t2"
	if err := r.Submit(tk); err != nil {
		t.Fatalf("submit after the first run ended: %v", err)
	}
	f.wait(t, "DEV-1")
	if got := f.attempt("DEV-1"); got != 2 {
		t.Errorf("the second run was started as attempt %d, want 2", got)
	}
	r.Shutdown(context.Background())
	if err := r.Submit(newTask()); err != ErrStopped {
		t.Fatalf("submit after shutdown: got %v", err)
	}
}

// finished is a Notifier that collects the result of each task by ticket key.
type finished struct {
	mu      sync.Mutex
	res     map[string]task.Result
	started map[string]int // attempt number, by ticket key
	done    chan string    // receives the key of each finished task, if set
}

func (f *finished) Started(_ context.Context, t *task.Task) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started == nil {
		f.started = map[string]int{}
	}
	f.started[t.Key] = t.Attempt
	return nil
}

func (f *finished) Finished(_ context.Context, t *task.Task, res task.Result) error {
	f.mu.Lock()
	if f.res == nil {
		f.res = map[string]task.Result{}
	}
	f.res[t.Key] = res
	f.mu.Unlock()
	if f.done != nil {
		f.done <- t.Key
	}
	return nil
}

func (f *finished) wait(t *testing.T, key string) {
	t.Helper()
	select {
	case got := <-f.done:
		if got != key {
			t.Fatalf("task %s finished, want %s", got, key)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("task %s did not finish", key)
	}
}

func (f *finished) task(key string) *task.Task {
	tk := newTask()
	tk.ID, tk.Key = "t-"+key, key
	return tk
}

func (f *finished) result(key string) task.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.res[key]
}

func (f *finished) outcome(key string) task.Outcome { return f.result(key).Outcome }

// attempt returns the attempt number the ticket's last run was started with.
func (f *finished) attempt(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started[key]
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

// A shutdown waits for the running agent, and starts nothing new. What was
// queued stays queued, and runs after a restart.
func TestShutdownDrains(t *testing.T) {
	cfg := agentCfg(t, "nap")
	path := filepath.Join(t.TempDir(), "ochell.db")
	st := openStore(t, path)
	r, _ := New(cfg, logger(), st)
	f := &finished{}
	r.SetNotifier(f)
	for i, key := range []string{"A-1", "A-2"} {
		tk := f.task(key)
		tk.Received = time.Now().Add(time.Duration(i) * time.Second)
		if err := r.Submit(tk); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	waitRunning(t, r, cfg.LogDir, "t-A-1")
	r.Shutdown(context.Background())
	if got := f.outcome("A-1"); got != task.OutcomeFinished {
		t.Errorf("running task: outcome %q, want finished: the shutdown must wait for it", got)
	}
	if got := f.outcome("A-2"); got != "" {
		t.Errorf("queued task: outcome %q, want none: it must not be started or reported", got)
	}
	if n := r.Running(); n != 1 {
		t.Errorf("Running() = %d after shutdown, want the 1 queued task", n)
	}
	st.Close()

	// The restart: a new runner on the same store runs the queued task.
	r2, _ := New(cfg, logger(), openStore(t, path))
	f2 := &finished{done: make(chan string, 1)}
	r2.SetNotifier(f2)
	if err := r2.Start(); err != nil {
		t.Fatal(err)
	}
	f2.wait(t, "A-2")
	if got := f2.outcome("A-2"); got != task.OutcomeFinished {
		t.Errorf("queued task after the restart: outcome %q, want finished", got)
	}
	r2.Shutdown(context.Background())
}

// A run that was in progress when ochell died is closed at the next start,
// and its ticket is told. Another run takes its place, with the recovery
// note in its prompt.
func TestStartResumesInterruptedRuns(t *testing.T) {
	cfg := agentCfg(t, "echo")
	cfg.PromptTemplate = "Fix {{.Key}}\n{{.RunContext}}"
	cfg.MaxAttempts = 5
	path := filepath.Join(t.TempDir(), "ochell.db")
	st := openStore(t, path)
	if err := st.Enqueue(newTask(), store.Limits{}); err != nil {
		t.Fatal(err)
	}
	if tk, err := st.Claim(); err != nil || tk == nil {
		t.Fatalf("Claim = %v, %v", tk, err)
	}
	// ochell is killed here: the run stays "running" in the store.

	st2 := openStore(t, path)
	r, _ := New(cfg, logger(), st2)
	f := &finished{done: make(chan string, 2)}
	r.SetNotifier(f)
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	// Two reports: the interrupted run, and the run that took its place.
	f.wait(t, "DEV-1")
	f.wait(t, "DEV-1")
	r.Shutdown(context.Background())
	if got := f.attempt("DEV-1"); got != 2 {
		t.Errorf("the run after the restart was attempt %d, want 2", got)
	}
	if res := f.result("DEV-1"); res.Outcome != task.OutcomeFinished {
		t.Errorf("the run after the restart: %+v, want finished", res)
	}
	if old, _ := st2.Run("t1"); old == nil || old.Result.Outcome != task.OutcomeInterrupted {
		t.Errorf("the interrupted run = %+v", old)
	}
	logs, _ := filepath.Glob(filepath.Join(cfg.LogDir, "*.log"))
	if len(logs) != 1 {
		t.Fatalf("log files = %v, want that of the new run only", logs)
	}
	raw, _ := os.ReadFile(logs[0])
	if !strings.Contains(string(raw), "The orchestrator was restarted while you were working on this ticket") {
		t.Errorf("the prompt of the new run has no recovery note:\n%s", raw)
	}
}

// A ticket that has used up its attempts is not started again after a
// restart: it waits, and is told that its run was cut off.
func TestStartDoesNotResumeAtTheAttemptCap(t *testing.T) {
	cfg := agentCfg(t, "echo")
	cfg.MaxAttempts = 1
	path := filepath.Join(t.TempDir(), "ochell.db")
	st := openStore(t, path)
	if err := st.Enqueue(newTask(), store.Limits{}); err != nil {
		t.Fatal(err)
	}
	if tk, err := st.Claim(); err != nil || tk == nil {
		t.Fatalf("Claim = %v, %v", tk, err)
	}

	r, _ := New(cfg, logger(), openStore(t, path))
	f := &finished{done: make(chan string, 1)}
	r.SetNotifier(f)
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	f.wait(t, "DEV-1")
	res := f.result("DEV-1")
	if res.Outcome != task.OutcomeInterrupted || res.Err == nil || res.Next != "" {
		t.Errorf("result = %+v, want interrupted, with an error and no next run", res)
	}
	if f.attempt("DEV-1") != 0 {
		t.Error("the interrupted run was started again")
	}
	r.Shutdown(context.Background())
}

// When the wait is over, the running agent is stopped.
func TestShutdownStopsAfterTheWait(t *testing.T) {
	cfg := agentCfg(t, "sleep")
	cfg.Timeout = time.Minute
	r, _ := New(cfg, logger(), testStore(t))
	f := &finished{}
	r.SetNotifier(f)
	if err := r.Submit(f.task("B-1")); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
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
	if _, err := New(cfg, logger(), testStore(t)); err == nil {
		t.Fatal("expected template parse error")
	}
}

// Which failed runs ochell starts again by itself, and after what wait.
func TestRetryDecision(t *testing.T) {
	cfg := agentCfg(t, "echo")
	cfg.MaxAttempts = 5
	cfg.Retry = config.Retry{Patterns: config.DefaultRetryPatterns, Backoff: time.Minute, MaxBackoff: 10 * time.Minute}
	r, err := New(cfg, logger(), testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	failed := func(msg string) task.Result { return task.Result{Outcome: task.OutcomeFailed, Message: msg} }
	for name, c := range map[string]struct {
		res  task.Result
		want task.Cause
	}{
		"rate limit":         {failed("API Error: 429 {\"type\":\"rate_limit_error\"}"), task.CauseRetry},
		"overloaded":         {failed("API Error (529): Overloaded"), task.CauseRetry},
		"gateway":            {failed("upstream: 502 Bad Gateway"), task.CauseRetry},
		"connection":         {failed("read tcp: connection reset by peer"), task.CauseRetry},
		"a task failure":     {failed("error: 3 tests failed in line 500"), ""},
		"no output":          {failed(""), ""},
		"stalled":            {task.Result{Outcome: task.OutcomeStalled}, task.CauseStalled},
		"shutdown":           {task.Result{Outcome: task.OutcomeStopped, Message: "rate limit"}, task.CauseRecovery},
		"timed out":          {task.Result{Outcome: task.OutcomeTimedOut, Message: "rate limit"}, ""},
		"finished":           {task.Result{Outcome: task.OutcomeFinished, Message: "I hit a rate limit and waited."}, ""},
		"could not start it": {task.Result{Outcome: task.OutcomeNotStarted, Message: "overloaded"}, ""},
	} {
		again, ok := r.next(&task.Task{Source: "jira", Key: "DEV-1", Attempt: 1}, c.res)
		if ok != (c.want != "") || again.Cause != c.want {
			t.Errorf("%s: next = %+v, %v; want cause %q", name, again, ok, c.want)
		}
		if ok && again.MaxAttempts != 5 {
			t.Errorf("%s: the attempt cap was not passed on: %+v", name, again)
		}
		// Only what ochell retries waits; a recovery starts at once.
		if wantWait := c.want == task.CauseRetry || c.want == task.CauseStalled; wantWait != !again.NotBefore.IsZero() {
			t.Errorf("%s: NotBefore = %v", name, again.NotBefore)
		}
	}
	for attempt, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 4: 8 * time.Minute, 5: 10 * time.Minute, 60: 10 * time.Minute} {
		if got := r.backoff(attempt); got != want {
			t.Errorf("backoff after attempt %d = %s, want %s", attempt, got, want)
		}
	}
}

// A run that says nothing for stall_timeout is stopped as stalled; one that
// keeps writing is not.
func TestStallDetection(t *testing.T) {
	cfg := agentCfg(t, "sleep")
	cfg.StallTimeout = 300 * time.Millisecond
	r, _ := New(cfg, logger(), testStore(t))
	start := time.Now()
	res := r.Run(context.Background(), newTask())
	if res.Outcome != task.OutcomeStalled || res.Err == nil || !strings.Contains(res.Err.Error(), "wrote no output for 300ms") {
		t.Errorf("silent agent: %+v, want stalled", res)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("the stalled agent was stopped after %s", d)
	}

	cfg = agentCfg(t, "chatty")
	cfg.StallTimeout = 300 * time.Millisecond
	r, _ = New(cfg, logger(), testStore(t))
	if res := r.Run(context.Background(), newTask()); res.Outcome != task.OutcomeFinished {
		t.Errorf("an agent that keeps writing: %+v, want finished", res)
	}
}
