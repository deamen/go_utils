package runner

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"ochell/internal/config"
)

// Retention: what runs leave behind does not stay for ever. A run log holds
// the prompt and ticket text, and a run directory the agent's result file.
// Both are removed when they are older than retention.logs. The working
// directory of a closed ticket is removed when the ticket is closed
// (workspace.cleanup); the sweep takes the ones that this missed, because
// the removal failed or ochell was not running.

// UseRetention sets how long logs are kept and how often ochell looks.
// Call it before Start. Without it nothing is removed.
func (r *Runner) UseRetention(cfg config.Retention) { r.retention = cfg }

// runRetention sweeps at once and then at every interval, until Shutdown.
func (r *Runner) runRetention() {
	defer r.wg.Done()
	tick := time.NewTicker(r.retention.Interval)
	defer tick.Stop()
	for {
		r.Sweep(time.Now())
		select {
		case <-r.quit:
			return
		case <-tick.C:
		}
	}
}

// Sweep removes the run logs and run directories that were last written
// more than retention.logs before now, and the working directories of
// closed tickets that are still there.
func (r *Runner) Sweep(now time.Time) {
	if keep := r.retention.Logs; keep > 0 {
		before := now.Add(-keep)
		logs := r.sweepDir(r.cfg.LogDir, before, func(e os.DirEntry) bool { return !e.IsDir() && strings.HasSuffix(e.Name(), ".log") },
			func(path, _ string) error { return os.Remove(path) })
		runs := r.sweepDir(r.runDir, before, func(e os.DirEntry) bool { return e.IsDir() },
			func(path, _ string) error { return os.RemoveAll(path) })
		if logs+runs > 0 {
			r.log.Info("retention: removed what is older than retention.logs", "logs", logs, "run_directories", runs, "older_than", keep)
		}
	}
	if !r.ws.cfg.Cleanup || r.ws.root == "" {
		return
	}
	left, err := r.store.ClosedWithWorkspace()
	if err != nil {
		r.log.Error("retention: cannot read the closed tickets", "err", err)
		return
	}
	for _, tk := range left {
		select {
		case <-r.quit:
			return
		default:
		}
		r.log.Info("retention: removing the working directory of a closed ticket that is still there", "source", tk.Source, "key", tk.Key)
		r.removeWorkspace(tk.Source, tk.Key)
	}
}

// sweepDir removes the entries of dir that match and were last modified
// before the given time, and returns how many it removed.
func (r *Runner) sweepDir(dir string, before time.Time, match func(os.DirEntry) bool, remove func(path, name string) error) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			r.log.Warn("retention: cannot read the directory", "dir", dir, "err", err)
		}
		return 0
	}
	removed := 0
	for _, e := range entries {
		if !match(e) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(before) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := remove(path, e.Name()); err != nil {
			r.log.Warn("retention: cannot remove", "path", path, "err", err)
			continue
		}
		removed++
	}
	return removed
}
