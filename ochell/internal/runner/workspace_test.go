package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ochell/internal/config"
	"ochell/internal/store"
	"ochell/internal/task"
	"ochell/internal/ticket"
)

// helper returns the command line of the test helper in a mode, for a hook.
func helper(mode ...string) []string {
	return append([]string{os.Args[0], "-test.run=TestHelperAgent", "--"}, mode...)
}

// workspaceRunner is a runner whose agent and hooks note in a file that
// they ran. root is the workspace root.
type workspaceRunner struct {
	*Runner
	st    *store.Store
	done  *finished
	root  string
	marks string
}

func newWorkspaceRunner(t *testing.T, ws config.Workspace) *workspaceRunner {
	t.Helper()
	dir := t.TempDir()
	w := &workspaceRunner{root: filepath.Join(dir, "work"), marks: filepath.Join(dir, "marks"), st: testStore(t)}
	cfg := agentCfg(t, "mark", "agent")
	cfg.Workdir = filepath.Join(w.root, "{{.Key}}")
	cfg.Env["ORCH_TEST_MARKS"] = w.marks
	r, err := New(cfg, logger(), w.st)
	if err != nil {
		t.Fatal(err)
	}
	ws.Root = w.root
	if ws.Branch == "" {
		ws.Branch = "bot/{{.Key}}"
	}
	if ws.HookTimeout == 0 {
		ws.HookTimeout = 10 * time.Second
	}
	if err := r.UseWorkspace(ws); err != nil {
		t.Fatal(err)
	}
	w.Runner, w.done = r, &finished{done: make(chan string, 8)}
	r.SetNotifier(w.done)
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Shutdown(context.Background()) })
	return w
}

// run submits a task for DEV-1 and waits for it to end.
func (w *workspaceRunner) run(t *testing.T, id string) task.Result {
	t.Helper()
	tk := newTask()
	tk.ID = id
	if err := w.Submit(tk); err != nil {
		t.Fatal(err)
	}
	w.done.wait(t, "DEV-1")
	return w.done.result("DEV-1")
}

// ran returns what ran, in order, as "name in dir branch=… hook=…" lines.
func (w *workspaceRunner) ran(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(w.marks)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// after_create runs once for a working directory, before_run and after_run
// around every run, all in the working directory and with the branch.
func TestWorkspaceHooks(t *testing.T) {
	w := newWorkspaceRunner(t, config.Workspace{Hooks: config.Hooks{
		AfterCreate: helper("mark", "after_create"),
		BeforeRun:   helper("mark", "before_run"),
		AfterRun:    helper("mark", "after_run"),
	}})
	first := w.run(t, "t1")
	if first.Outcome != task.OutcomeFinished {
		t.Fatalf("first run: %+v", first)
	}
	second := w.run(t, "t2")
	if second.Outcome != task.OutcomeFinished {
		t.Fatalf("second run: %+v", second)
	}
	want := []string{
		"after_create in DEV-1 branch=bot/DEV-1 hook=after_create",
		"before_run in DEV-1 branch=bot/DEV-1 hook=before_run",
		"agent in DEV-1 branch=bot/DEV-1 hook=",
		"after_run in DEV-1 branch=bot/DEV-1 hook=after_run",
		// The second run reuses the directory: no after_create.
		"before_run in DEV-1 branch=bot/DEV-1 hook=before_run",
		"agent in DEV-1 branch=bot/DEV-1 hook=",
		"after_run in DEV-1 branch=bot/DEV-1 hook=after_run",
	}
	if got := w.ran(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ran:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	logged, _ := os.ReadFile(first.LogFile)
	for _, wantLine := range []string{"# ---- hook after_create: ", "# ---- hook before_run: ", "# ---- agent output ----", "# ---- hook after_run: err=<nil>"} {
		if !strings.Contains(string(logged), wantLine) {
			t.Errorf("the run log lacks %q:\n%s", wantLine, logged)
		}
	}
	if tk, _ := w.st.Ticket("jira", "DEV-1"); tk.PreparedWorkspace != filepath.Join(w.root, "DEV-1") {
		t.Errorf("prepared working directory = %q", tk.PreparedWorkspace)
	}
}

// A hook that fails before the agent keeps the agent from starting, and
// after_create is tried again by the next run.
func TestWorkspaceHookFailure(t *testing.T) {
	w := newWorkspaceRunner(t, config.Workspace{Hooks: config.Hooks{
		AfterCreate: helper("mark", "after_create", "fail"),
		AfterRun:    helper("mark", "after_run"),
	}})
	for _, id := range []string{"t1", "t2"} {
		res := w.run(t, id)
		if res.Outcome != task.OutcomeNotStarted || res.Err == nil || !strings.Contains(res.Err.Error(), "workspace hook after_create: exit status 4") {
			t.Errorf("%s: outcome %s, err %v", id, res.Outcome, res.Err)
		}
	}
	want := "after_create in DEV-1 branch=bot/DEV-1 hook=after_create"
	if got := w.ran(t); len(got) != 2 || got[0] != want || got[1] != want {
		t.Errorf("ran %q, want after_create twice and nothing else", got)
	}
	if tk, _ := w.st.Ticket("jira", "DEV-1"); tk.State != ticket.Failed || tk.PreparedWorkspace != "" {
		t.Errorf("ticket = %s, prepared %q", tk.State, tk.PreparedWorkspace)
	}

	// A failing after_run does not change how the run ended.
	w = newWorkspaceRunner(t, config.Workspace{Hooks: config.Hooks{AfterRun: helper("mark", "after_run", "fail")}})
	if res := w.run(t, "t1"); res.Outcome != task.OutcomeFinished || res.Err != nil {
		t.Errorf("run with a failing after_run: outcome %s, err %v", res.Outcome, res.Err)
	}

	// A hook that does not come back is stopped at its time limit.
	w = newWorkspaceRunner(t, config.Workspace{HookTimeout: 200 * time.Millisecond, Hooks: config.Hooks{BeforeRun: helper("sleep")}})
	if res := w.run(t, "t1"); res.Outcome != task.OutcomeNotStarted || !strings.Contains(res.Err.Error(), "workspace hook before_run: timed out") {
		t.Errorf("hook over its time limit: outcome %s, err %v", res.Outcome, res.Err)
	}
}

// A working directory outside the root is refused before anything is
// created or started.
func TestWorkdirOutsideRootIsRefused(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere")
	for name, workdir := range map[string]string{
		"another directory": filepath.Join(outside, "{{.Key}}"),
		"a sibling prefix":  "ROOT-other/{{.Key}}",
		"dots out":          "ROOT/../elsewhere/{{.Key}}",
		"relative":          "work/{{.Key}}",
	} {
		cfg := agentCfg(t, "echo")
		root := filepath.Join(filepath.Dir(cfg.LogDir), "work")
		cfg.Workdir = strings.ReplaceAll(workdir, "ROOT", root)
		r, _ := New(cfg, logger(), testStore(t))
		if err := r.UseWorkspace(config.Workspace{Root: root, Branch: "bot/{{.Key}}", HookTimeout: time.Second}); err != nil {
			t.Fatal(err)
		}
		res := r.Run(context.Background(), newTask())
		if res.Outcome != task.OutcomeNotStarted || res.Err == nil || !strings.Contains(res.Err.Error(), "outside workspace.root") {
			t.Errorf("%s: outcome %s, err %v", name, res.Outcome, res.Err)
		}
		if res.LogFile != "" {
			t.Errorf("%s: a run was prepared: %s", name, res.LogFile)
		}
	}
	if _, err := os.Stat(outside); err == nil {
		t.Error("a directory was created outside the root")
	}
	// Inside the root, and the root itself, are fine.
	for _, dir := range []string{"/work", "/work/a", "/work/a/b"} {
		if !within("/work", dir) {
			t.Errorf("within(/work, %s) = false", dir)
		}
	}
	for _, dir := range []string{"/", "/workshop", "/other/work"} {
		if within("/work", dir) {
			t.Errorf("within(/work, %s) = true", dir)
		}
	}
}

func waitGone(t *testing.T, dir string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not removed", dir)
		}
	}
}

// When the tracker reports a ticket as closed, its working directory is
// removed and the ticket is done.
func TestClosedTicketWorkspaceIsRemoved(t *testing.T) {
	w := newWorkspaceRunner(t, config.Workspace{Cleanup: true, Hooks: config.Hooks{
		AfterCreate:  helper("mark", "after_create"),
		BeforeRemove: helper("mark", "before_remove"),
	}})
	dir := filepath.Join(w.root, "DEV-1")

	if err := w.Closed("jira", "DEV-1"); !errors.Is(err, store.ErrUnknown) {
		t.Errorf("closing a ticket ochell never saw: %v, want ErrUnknown", err)
	}
	w.run(t, "t1")
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := w.Closed("jira", "DEV-1"); err != nil {
		t.Fatal(err)
	}
	waitGone(t, dir)
	if _, err := os.Stat(w.root); err != nil {
		t.Errorf("the root itself must stay: %v", err)
	}
	// The removal is recorded a moment after the directory is gone.
	var tk *store.Ticket
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if tk, _ = w.st.Ticket("jira", "DEV-1"); tk.Workspace == "" {
			break
		}
	}
	if tk.State != ticket.Done || tk.Workspace != "" || tk.PreparedWorkspace != "" || tk.AgentSession != "" {
		t.Errorf("ticket after the close = %+v, want done without a working directory", tk)
	}
	if got := w.ran(t); len(got) != 3 || got[2] != "before_remove in DEV-1 branch=bot/DEV-1 hook=before_remove" {
		t.Errorf("ran %q, want before_remove last", got)
	}
	// A second report of the same close changes nothing.
	if err := w.Closed("jira", "DEV-1"); err != nil {
		t.Errorf("closing a done ticket again: %v", err)
	}

	// Assigned again, the ticket gets a new working directory.
	w.run(t, "t2")
	if got := w.ran(t); len(got) != 5 || !strings.HasPrefix(got[3], "after_create ") {
		t.Errorf("ran %q, want after_create again for the new directory", got)
	}
}

func TestClosedTicketIsKeptWhenItShouldBe(t *testing.T) {
	// Without workspace.cleanup the directory stays.
	w := newWorkspaceRunner(t, config.Workspace{})
	w.run(t, "t1")
	if err := w.Closed("jira", "DEV-1"); err != nil {
		t.Fatal(err)
	}
	w.Shutdown(context.Background())
	if _, err := os.Stat(filepath.Join(w.root, "DEV-1")); err != nil {
		t.Errorf("the working directory was removed without workspace.cleanup: %v", err)
	}
	if tk, _ := w.st.Ticket("jira", "DEV-1"); tk.State != ticket.Done {
		t.Errorf("ticket = %s, want done", tk.State)
	}

	// A ticket that is closed while its task is queued is not started.
	st := testStore(t)
	r, _ := New(agentCfg(t, "echo"), logger(), st)
	f := &finished{done: make(chan string, 1)}
	r.SetNotifier(f)
	if err := r.Submit(newTask()); err != nil {
		t.Fatal(err)
	}
	if err := r.Closed("jira", "DEV-1"); err != nil {
		t.Errorf("closing a queued ticket: %v", err)
	}
	if tk, _ := st.Ticket("jira", "DEV-1"); tk.State != ticket.Done {
		t.Errorf("ticket = %s, want done", tk.State)
	}
	if run, _ := st.Run("t1"); run == nil || run.Status != "ended" || run.Result.Outcome != task.OutcomeCancelled {
		t.Errorf("the queued run = %+v, want ended as cancelled", run)
	}
	f.wait(t, "DEV-1")
	if res := f.result("DEV-1"); res.Outcome != task.OutcomeCancelled || res.Err == nil || !strings.Contains(res.Err.Error(), "the ticket was closed") {
		t.Errorf("the ticket was told %+v", res)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	r.Shutdown(context.Background())
	if f.attempt("DEV-1") != 0 {
		t.Error("the run of the closed ticket was started")
	}
}

func TestWorkspaceSettings(t *testing.T) {
	r, _ := New(agentCfg(t, "echo"), logger(), testStore(t))
	ok := config.Workspace{Branch: "bot/{{.Source}}-{{.Key}}", HookTimeout: time.Second, Hooks: config.Hooks{
		AfterCreate: []string{"/usr/bin/git", "clone", "{{.Repo}}", "."},
		BeforeRun:   []string{"/usr/bin/git", "checkout", "{{.Branch}}"},
	}}
	if err := r.UseWorkspace(ok); err != nil {
		t.Fatalf("valid settings: %v", err)
	}
	if got := r.ws.view(&task.Task{Source: "jira", Key: "DEV-1"}).Branch; got != "bot/jira-DEV-1" {
		t.Errorf("branch = %q", got)
	}
	// Ticket text must not reach a hook's command line.
	for _, field := range []string{".Title", ".Context", ".Comment", ".Prompt"} {
		bad := ok
		bad.Hooks.BeforeRun = []string{"/bin/echo", "{{" + field + "}}"}
		if err := r.UseWorkspace(bad); err == nil {
			t.Errorf("{{%s}} in a hook must be refused", field)
		}
	}
	bad := ok
	bad.Branch = "bot/{{.Title}}"
	if err := r.UseWorkspace(bad); err == nil {
		t.Error("{{.Title}} in the branch must be refused")
	}
}
