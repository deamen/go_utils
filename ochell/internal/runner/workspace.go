package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"ochell/internal/config"
	"ochell/internal/launcher"
	"ochell/internal/task"
)

// workspace is the configured life of a ticket's working directory: where
// it may be, the hooks that prepare it, and its removal.
//
// The hooks are ochell's own. They run in the working directory through the
// launcher, so as the same OS user as the agent, and the agent owns what
// they create.
type workspace struct {
	cfg    config.Workspace
	root   string // cleaned; empty: no root
	branch *template.Template
	hooks  map[string][]*template.Template
}

// hookView is what the hook and branch templates see: nothing that can hold
// ticket text, because the values become command-line arguments.
type hookView struct {
	ID     string
	Source string
	Key    string
	// Repo is the repository mapped to the ticket.
	Repo string
	// Branch is the branch the ticket is worked on.
	Branch string
}

func newWorkspace(cfg config.Workspace) (*workspace, error) {
	w := &workspace{cfg: cfg, hooks: map[string][]*template.Template{}}
	if cfg.Root != "" {
		w.root = filepath.Clean(cfg.Root)
	}
	var err error
	if w.branch, err = parse("workspace.branch", cfg.Branch); err != nil {
		return nil, err
	}
	probe := hookView{ID: "id", Source: "source", Key: "KEY-1", Repo: "repo", Branch: "branch"}
	if _, err := render(w.branch, probe); err != nil {
		return nil, fmt.Errorf("workspace.branch: only .Source and .Key may be used: %w", err)
	}
	for _, h := range cfg.Hooks.All() {
		for i, a := range h.Command {
			t, err := parse(fmt.Sprintf("workspace.hooks.%s[%d]", h.Name, i), a)
			if err != nil {
				return nil, err
			}
			if _, err := render(t, probe); err != nil {
				return nil, fmt.Errorf("workspace.hooks.%s: only .ID, .Source, .Key, .Repo and .Branch may be used: %w", h.Name, err)
			}
			w.hooks[h.Name] = append(w.hooks[h.Name], t)
		}
	}
	return w, nil
}

// UseWorkspace sets the workspace settings. Call it before Start. Without
// it there is no root, no hook and no cleanup.
func (r *Runner) UseWorkspace(cfg config.Workspace) error {
	w, err := newWorkspace(cfg)
	if err != nil {
		return err
	}
	r.ws = w
	return nil
}

// within reports whether dir is root or inside it. Both are cleaned paths.
func within(root, dir string) bool {
	return dir == root || strings.HasPrefix(dir, root+string(filepath.Separator))
}

// check refuses a working directory outside the root.
func (w *workspace) check(dir string) error {
	if w.root == "" {
		return nil
	}
	if !filepath.IsAbs(dir) || !within(w.root, filepath.Clean(dir)) {
		return fmt.Errorf("the working directory %s is outside workspace.root %s", dir, w.root)
	}
	return nil
}

func (w *workspace) view(t *task.Task) hookView {
	v := hookView{ID: t.ID, Source: t.Source, Key: t.Key, Repo: t.Repo}
	v.Branch, _ = render(w.branch, v)
	return v
}

// hook runs one workspace hook in dir and writes its output to out. unit
// names the run for the launcher. It returns nil when there is no such
// hook, and an error that names the hook when it does not succeed.
func (r *Runner) hook(ctx context.Context, name string, t *task.Task, dir, unit string, out io.Writer) error {
	tmpl := r.ws.hooks[name]
	if len(tmpl) == 0 {
		return nil
	}
	view := r.ws.view(t)
	argv := make([]string, len(tmpl))
	for i, a := range tmpl {
		s, err := render(a, view)
		if err != nil {
			return fmt.Errorf("workspace hook %s: %w", name, err)
		}
		argv[i] = s
	}
	start := time.Now()
	fmt.Fprintf(out, "# ---- hook %s: %s (%d args) ----\n", name, argv[0], len(argv)-1)
	spec := launcher.Spec{
		TaskID:    unit + "." + name,
		Command:   argv[0],
		Args:      argv[1:],
		Dir:       dir,
		Env:       append(r.taskEnv(t), "ORCH_HOOK="+name),
		Inherited: r.inheritedEnv(),
		Output:    out,
		Timeout:   r.ws.cfg.HookTimeout,
	}
	w, outcome := r.execute(ctx, spec)
	var err error
	switch {
	case outcome == task.OutcomeTimedOut:
		err = fmt.Errorf("timed out after %s", r.ws.cfg.HookTimeout)
	case outcome == task.OutcomeStopped:
		err = errors.New("stopped because ochell is shutting down")
	case w.err != nil:
		err = w.err
	case w.code != 0:
		err = fmt.Errorf("exit status %d", w.code)
	}
	fmt.Fprintf(out, "\n# ---- hook %s: err=%v duration=%s ----\n", name, err, time.Since(start).Round(time.Millisecond))
	if err != nil {
		return fmt.Errorf("workspace hook %s: %w", name, err)
	}
	return nil
}

// prepare runs the hooks that come before the agent: after_create once for
// a working directory, before_run every time.
func (r *Runner) prepare(ctx context.Context, t *task.Task, dir, unit string, out io.Writer) error {
	if len(r.ws.hooks["after_create"]) > 0 && t.PreparedWorkspace != dir {
		if err := r.hook(ctx, "after_create", t, dir, unit, out); err != nil {
			return err
		}
		t.PreparedWorkspace = dir
		if err := r.store.SetPrepared(t.Source, t.Key, dir); err != nil {
			return fmt.Errorf("record the prepared working directory: %w", err)
		}
	}
	return r.hook(ctx, "before_run", t, dir, unit, out)
}

// ticketLocks serialises what happens in the working directory of one
// ticket: a run and the removal of the directory must not overlap.
type ticketLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func (l *ticketLocks) lock(source, key string) (unlock func()) {
	l.mu.Lock()
	if l.m == nil {
		l.m = map[string]*sync.Mutex{}
	}
	k := source + ":" + key
	m := l.m[k]
	if m == nil {
		m = &sync.Mutex{}
		l.m[k] = m
	}
	l.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// Closed is called when the tracker reports a ticket as closed. The ticket
// becomes done where its state allows, and with workspace.cleanup its
// working directory is removed, in the background.
//
// It returns ErrBusy for a ticket with a queued or running task: stopping a
// run is not supported yet, so such a ticket is left as it is. It returns
// store.ErrUnknown for a ticket ochell has never seen.
func (r *Runner) Closed(source, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	tk, err := r.store.CloseTicket(source, key)
	if err != nil {
		return err
	}
	r.log.Info("ticket closed in the tracker", "source", source, "key", key, "state", tk.State)
	if r.ws.cfg.Cleanup && r.ws.root != "" && (tk.Workspace != "" || tk.PreparedWorkspace != "") {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.removeWorkspace(source, key)
		}()
	}
	return nil
}

// removeWorkspace removes the working directory of a closed ticket, as the
// OS user that owns it.
func (r *Runner) removeWorkspace(source, key string) {
	log := r.log.With("source", source, "key", key)
	defer r.locks.lock(source, key)()
	// Read the ticket again: it may have been started in the meantime.
	tk, err := r.store.Ticket(source, key)
	if err != nil || tk == nil {
		log.Error("cannot remove the working directory: the ticket cannot be read", "err", err)
		return
	}
	if tk.State.Active() {
		log.Info("the working directory is kept: the ticket was started again")
		return
	}
	dir := tk.Workspace
	if dir == "" {
		dir = tk.PreparedWorkspace
	}
	if dir == "" {
		return
	}
	// Never the root itself, and nothing outside it.
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(dir) || clean == r.ws.root || !within(r.ws.root, clean) {
		log.Error("the working directory is not removed: it is not a directory inside workspace.root", "dir", dir, "root", r.ws.root)
		return
	}

	t := &task.Task{ID: fmt.Sprintf("%s-%s-%s", time.Now().UTC().Format("20060102T150405.000Z"), source, key), Source: source, Key: key, URL: tk.URL, Repo: tk.Repo}
	unit := unsafeName.ReplaceAllString(t.ID, "_") + ".remove"
	out := io.Discard
	if err := os.MkdirAll(r.cfg.LogDir, 0o750); err == nil {
		if lf, err := os.OpenFile(filepath.Join(r.cfg.LogDir, unit+".log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640); err == nil {
			defer lf.Close()
			out = lf
		}
	}
	fmt.Fprintf(out, "# removing the working directory %s of %s %s\n", clean, source, key)
	ctx := context.Background()
	if err := r.hook(ctx, "before_remove", t, clean, unit, out); err != nil {
		// The directory goes all the same: the ticket is closed.
		log.Warn("before_remove hook failed", "err", err)
	}
	if err := r.remove(ctx, clean, unit, out); err != nil {
		fmt.Fprintf(out, "# not removed: %v\n", err)
		log.Error("cannot remove the working directory", "dir", clean, "err", err)
		return
	}
	if err := r.store.ClearWorkspace(source, key); err != nil {
		log.Error("cannot record the removal of the working directory", "err", err)
	}
	fmt.Fprintf(out, "# removed\n")
	log.Info("working directory removed", "dir", clean)
}

// remove deletes dir. With the direct launcher the files belong to ochell's
// own user. With the systemd launcher they belong to the agent user, so rm
// runs as that user, through the launcher, from the root.
func (r *Runner) remove(ctx context.Context, dir, unit string, out io.Writer) error {
	if r.cfg.Launcher != "systemd" {
		return os.RemoveAll(dir)
	}
	spec := launcher.Spec{
		TaskID:  unit + ".rm",
		Command: "/bin/rm",
		Args:    []string{"-rf", "--", dir},
		Dir:     r.ws.root,
		Output:  out,
		Timeout: r.ws.cfg.HookTimeout,
	}
	w, outcome := r.execute(ctx, spec)
	switch {
	case outcome != task.OutcomeFinished:
		return fmt.Errorf("rm did not finish: %s", outcome)
	case w.err != nil:
		return w.err
	case w.code != 0:
		return fmt.Errorf("rm: exit status %d", w.code)
	}
	return nil
}
