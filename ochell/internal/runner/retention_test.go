package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ochell/internal/config"
	"ochell/internal/result"
	"ochell/internal/store"
	"ochell/internal/task"
)

// Run logs and run directories that are older than the limit are removed,
// and so is the working directory of a closed ticket that was left behind.
func TestSweep(t *testing.T) {
	cfg := agentCfg(t, "echo")
	root := filepath.Dir(cfg.LogDir)
	st := testStore(t)
	r, err := New(cfg, logger(), st)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UseWorkspace(config.Workspace{Root: filepath.Join(root, "work"), Branch: "bot/{{.Key}}", HookTimeout: time.Minute, Cleanup: true}); err != nil {
		t.Fatal(err)
	}
	r.UseRetention(config.Retention{Logs: 24 * time.Hour, Interval: time.Hour})
	now := time.Now()
	file := func(path string, age time.Duration) string {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-age)
		for _, p := range []string{path, filepath.Dir(path)} {
			if p != cfg.LogDir {
				if err := os.Chtimes(p, at, at); err != nil {
					t.Fatal(err)
				}
			}
		}
		return path
	}
	oldLog := file(filepath.Join(cfg.LogDir, "old.log"), 25*time.Hour)
	newLog := file(filepath.Join(cfg.LogDir, "new.log"), 23*time.Hour)
	other := file(filepath.Join(cfg.LogDir, "notes.txt"), 100*time.Hour)
	oldRun := file(filepath.Join(cfg.RunDir, "old-run", result.FileName), 48*time.Hour)
	newRun := file(filepath.Join(cfg.RunDir, "new-run", result.FileName), time.Hour)

	// A ticket that is done, whose working directory is still there.
	tk := &task.Task{ID: "t-A-1", Source: "jira", Key: "A-1", Received: now}
	if err := st.Enqueue(tk, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	st.Claim()
	work := filepath.Join(root, "work", "A-1")
	file(filepath.Join(work, "main.go"), time.Minute)
	if err := st.Finish("t-A-1", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done, Workdir: work}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CloseTicket("jira", "A-1"); err != nil {
		t.Fatal(err)
	}
	// One that waits keeps its directory.
	tk2 := &task.Task{ID: "t-A-2", Source: "jira", Key: "A-2", Received: now}
	st.Enqueue(tk2, store.Limits{})
	st.Claim()
	work2 := filepath.Join(root, "work", "A-2")
	file(filepath.Join(work2, "main.go"), time.Minute)
	st.Finish("t-A-2", task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput, Workdir: work2})

	r.Sweep(now)
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	for _, gone := range []string{oldLog, filepath.Dir(oldRun), work} {
		if exists(gone) {
			t.Errorf("%s is still there", gone)
		}
	}
	for _, kept := range []string{newLog, other, newRun, work2} {
		if !exists(kept) {
			t.Errorf("%s was removed", kept)
		}
	}
	if got, _ := st.Ticket("jira", "A-1"); got.Workspace != "" {
		t.Errorf("the removed working directory is still recorded: %q", got.Workspace)
	}
	// Without a limit nothing goes.
	r.UseRetention(config.Retention{Interval: time.Hour})
	r.Sweep(now.Add(1000 * time.Hour))
	if !exists(newLog) || !exists(newRun) {
		t.Error("logs were removed without a limit")
	}
	r.Shutdown(context.Background())
}
