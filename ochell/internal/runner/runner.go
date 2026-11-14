// Package runner queues tasks and launches the agent CLI for each of them.
//
// Exactly one agent process is started per task; any multi-agent work is
// managed by that agent. The command is executed without a shell, so ticket
// content can never be interpreted as shell syntax. A launcher (package
// launcher) starts and stops the process.
//
// The queue is in the store (package store), so queued tasks survive a
// restart of ochell.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"ochell/internal/config"
	"ochell/internal/launcher"
	"ochell/internal/store"
	"ochell/internal/task"
)

var (
	ErrBusy      = store.ErrBusy
	ErrQueueFull = store.ErrQueueFull
	ErrStopped   = errors.New("runner is stopped")
)

const tailSize = 4096

// Notifier tells the source of a task how its run went. The server
// implements it.
type Notifier interface {
	// Started is called when a worker picks the task up.
	Started(ctx context.Context, t *task.Task) error
	// Finished is called when the run has ended, in any way.
	Finished(ctx context.Context, t *task.Task, res task.Result) error
}

type Runner struct {
	cfg      config.Agent
	log      *slog.Logger
	store    *store.Store
	notify   Notifier
	launcher launcher.Launcher
	prompt   *template.Template
	args     []*template.Template
	workdir  *template.Template
	mu       sync.Mutex
	stopped  bool
	wg       sync.WaitGroup
	// wake tells an idle worker to look at the queue.
	wake chan struct{}
	// quit is closed when Shutdown begins: workers start no more tasks.
	quit chan struct{}
	// runCtx is cancelled to stop the agents that are still running.
	runCtx   context.Context
	stopRuns context.CancelFunc
}

// New returns a runner that keeps its queue in st.
func New(cfg config.Agent, log *slog.Logger, st *store.Store) (*Runner, error) {
	r := &Runner{cfg: cfg, log: log, store: st, wake: make(chan struct{}, 1), quit: make(chan struct{})}
	r.runCtx, r.stopRuns = context.WithCancel(context.Background())
	var err error
	if r.prompt, err = parse("prompt_template", cfg.PromptTemplate); err != nil {
		return nil, err
	}
	if r.workdir, err = parse("workdir", cfg.Workdir); err != nil {
		return nil, err
	}
	for i, a := range cfg.Args {
		t, err := parse(fmt.Sprintf("args[%d]", i), a)
		if err != nil {
			return nil, err
		}
		r.args = append(r.args, t)
	}
	if r.launcher, err = launcher.New(cfg); err != nil {
		return nil, err
	}
	if cfg.Launcher == "systemd" {
		// Fail at start, not on the first ticket, when a template uses a
		// field that argView does not have.
		probe := argView{ID: "id", Source: "source", Key: "KEY-1"}
		for _, t := range append([]*template.Template{r.workdir}, r.args...) {
			if _, err := render(t, probe); err != nil {
				return nil, fmt.Errorf("agent %s: with the systemd launcher only .ID, .Source and .Key may be used here, because ticket text must not reach the command line: %w", t.Name(), err)
			}
		}
	}
	return r, nil
}

// SetNotifier sets who is told about the runs. Call it before Start.
func (r *Runner) SetNotifier(n Notifier) { r.notify = n }

func parse(name, text string) (*template.Template, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("agent %s: %w", name, err)
	}
	return t, nil
}

func render(t *template.Template, data any) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Submit queues a task. It never blocks. It returns ErrBusy when the ticket
// already has a queued or running task, and ErrQueueFull when queue_size
// tasks are waiting.
func (r *Runner) Submit(t *task.Task) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	if err := r.store.Enqueue(t, max(r.cfg.QueueSize, 1)); err != nil {
		return err
	}
	r.wakeWorker()
	return nil
}

func (r *Runner) wakeWorker() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// idlePoll is how often an idle worker looks at the queue without being
// woken. It only matters after a store error.
const idlePoll = 30 * time.Second

// Start launches the worker pool. Shutdown ends it. Tasks that were queued
// before a restart are run; runs that the restart cut short are closed and
// their tickets told.
func (r *Runner) Start() error {
	interrupted, err := r.store.Recover()
	if err != nil {
		return fmt.Errorf("recover the task store: %w", err)
	}
	for _, t := range interrupted {
		r.log.Warn("run was interrupted: ochell stopped while the agent was running", "task", t.ID, "source", t.Source, "key", t.Key)
	}
	if len(interrupted) > 0 && r.notify != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for _, t := range interrupted {
				res := task.Result{Outcome: task.OutcomeInterrupted, ExitCode: -1, Err: store.ErrInterrupted}
				if err := r.notify.Finished(context.Background(), t, res); err != nil {
					r.log.Warn("finish notification failed", "task", t.ID, "err", err)
				}
			}
		}()
	}
	if n, err := r.store.Active(); err == nil && n > 0 {
		r.log.Info("tasks queued before the restart will be run", "tasks", n)
	}

	n := max(r.cfg.MaxConcurrent, 1)
	for range n {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				// A closed quit wins over a waiting task.
				select {
				case <-r.quit:
					return
				default:
				}
				t, err := r.store.Claim()
				if err != nil {
					r.log.Error("cannot read the task queue", "err", err)
				}
				if t != nil {
					// There may be more work for the other workers.
					r.wakeWorker()
					r.handle(r.runCtx, t)
					continue
				}
				select {
				case <-r.quit:
					return
				case <-r.wake:
				case <-time.After(idlePoll):
				}
			}
		}()
	}
	return nil
}

// Shutdown rejects new tasks and waits for the running agents to finish.
// When ctx is done first, it stops them and waits for that. Tasks that were
// queued but not started stay in the store and are run after a restart.
//
// Runs that a shutdown interrupts are not resumed after a restart.
func (r *Runner) Shutdown(ctx context.Context) {
	r.mu.Lock()
	already := r.stopped
	r.stopped = true
	r.mu.Unlock()
	if already {
		r.wg.Wait()
		return
	}
	close(r.quit)

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		r.log.Warn("stopping the agents that are still running")
		r.stopRuns()
		<-done
	}
	r.stopRuns()
	if n := r.Running(); n > 0 {
		r.log.Info("tasks stay queued for the next start", "tasks", n)
	}
}

// Running returns the number of tasks that are queued or running.
func (r *Runner) Running() int {
	n, err := r.store.Active()
	if err != nil {
		r.log.Error("cannot count the tasks", "err", err)
	}
	return n
}

func (r *Runner) handle(ctx context.Context, t *task.Task) {
	log := r.log.With("task", t.ID, "source", t.Source, "key", t.Key, "attempt", t.Attempt)

	notifyCtx := context.WithoutCancel(ctx)
	if r.notify != nil {
		if err := r.notify.Started(notifyCtx, t); err != nil {
			log.Warn("start notification failed", "err", err)
		}
	}
	res := r.Run(ctx, t)
	if res.Err != nil {
		log.Error("agent run did not succeed", "outcome", res.Outcome, "exit", res.ExitCode, "err", res.Err, "duration", res.Duration, "log", res.LogFile)
	} else {
		log.Info("agent finished", "duration", res.Duration, "log", res.LogFile)
	}
	// Record the end before telling the ticket, so the ticket is free for
	// a new run by the time someone reads the answer.
	if err := r.store.Finish(t.ID, res); err != nil {
		log.Error("cannot record the end of the run", "err", err)
	}
	if r.notify != nil {
		if err := r.notify.Finished(notifyCtx, t, res); err != nil {
			log.Warn("finish notification failed", "err", err)
		}
	}
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// argView is what argument and working directory templates see with the
// systemd launcher: only fields that cannot hold ticket text. systemd
// replaces ${VAR} in a unit's arguments from its environment, which holds
// the agent's token, so a ticket title of "${CLAUDE_CODE_OAUTH_TOKEN}" in an
// argument would put the real token on the command line.
type argView struct {
	ID     string
	Source string
	Key    string
}

// argData returns the template data for arguments and the working directory.
func (r *Runner) argData(t *task.Task) any {
	if r.cfg.Launcher == "systemd" {
		return argView{ID: t.ID, Source: t.Source, Key: t.Key}
	}
	return t
}

// stopWait is how long Run waits for an agent to exit after asking the
// launcher to stop it, beyond the grace period.
const stopWait = 45 * time.Second

type waitResult struct {
	code int
	err  error
}

// Run renders the prompt and executes the agent synchronously. Cancelling
// ctx stops the agent with all its processes.
func (r *Runner) Run(ctx context.Context, t *task.Task) (res task.Result) {
	start := time.Now()
	res.ExitCode = -1
	res.Outcome = task.OutcomeNotStarted
	defer func() { res.Duration = time.Since(start) }()

	var err error
	if t.Prompt, err = render(r.prompt, t); err != nil {
		res.Err = fmt.Errorf("render prompt: %w", err)
		return res
	}
	args := make([]string, 0, len(r.args))
	for _, a := range r.args {
		s, err := render(a, r.argData(t))
		if err != nil {
			res.Err = fmt.Errorf("render args: %w", err)
			return res
		}
		args = append(args, s)
	}
	dir, err := render(r.workdir, r.argData(t))
	if err != nil {
		res.Err = fmt.Errorf("render workdir: %w", err)
		return res
	}
	res.Workdir = dir

	if err := os.MkdirAll(r.cfg.LogDir, 0o750); err != nil {
		res.Err = fmt.Errorf("create log dir: %w", err)
		return res
	}
	res.LogFile = filepath.Join(r.cfg.LogDir, unsafeName.ReplaceAllString(t.ID, "_")+".log")
	lf, err := os.OpenFile(res.LogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		res.Err = fmt.Errorf("open log: %w", err)
		return res
	}
	defer lf.Close()
	fmt.Fprintf(lf, "# task=%s source=%s key=%s url=%s\n# command=%s (%d args) workdir=%s\n# prompt:\n%s\n# ---- agent output ----\n",
		t.ID, t.Source, t.Key, t.URL, r.cfg.Command, len(args), dir, t.Prompt)
	defer func() {
		fmt.Fprintf(lf, "\n# ---- exit=%d outcome=%s err=%v duration=%s ----\n", res.ExitCode, res.Outcome, res.Err, time.Since(start))
	}()

	tail := &tailBuffer{max: tailSize}
	spec := launcher.Spec{
		TaskID:    unsafeName.ReplaceAllString(t.ID, "_"),
		Command:   r.cfg.Command,
		Args:      args,
		Dir:       dir,
		Env:       r.taskEnv(t),
		Inherited: r.inheritedEnv(),
		Output:    io.MultiWriter(lf, tail),
		Timeout:   r.cfg.Timeout,
	}
	if r.cfg.PromptVia == "stdin" {
		spec.Stdin = strings.NewReader(t.Prompt)
	}
	proc, err := r.launcher.Start(spec)
	if err != nil {
		res.Err = err
		return res
	}
	waited := make(chan waitResult, 1)
	go func() {
		code, err := proc.Wait()
		waited <- waitResult{code, err}
	}()
	var timeout <-chan time.Time
	if r.cfg.Timeout > 0 {
		timer := time.NewTimer(r.cfg.Timeout)
		defer timer.Stop()
		timeout = timer.C
	}

	// Why the run ended is decided here, from what ochell asked for. The
	// exit code cannot tell: a unit that systemd stopped exits with 0, and
	// one that hit its own time limit exits with 1 like a failed agent.
	var w waitResult
	select {
	case w = <-waited:
		res.Outcome = task.OutcomeFinished
	case <-timeout:
		res.Outcome = task.OutcomeTimedOut
		w = r.stop(proc, waited)
	case <-ctx.Done():
		res.Outcome = task.OutcomeStopped
		w = r.stop(proc, waited)
	}
	res.Tail = tail.String()
	res.ExitCode = w.code
	switch {
	case res.Outcome == task.OutcomeTimedOut:
		res.Err = fmt.Errorf("agent timed out after %s", r.cfg.Timeout)
	case res.Outcome == task.OutcomeStopped:
		res.Err = errors.New("the agent was stopped because ochell is shutting down")
	case errors.Is(w.err, launcher.ErrNotStarted):
		res.Outcome = task.OutcomeNotStarted
		res.Err = w.err
	case w.err != nil:
		res.Outcome = task.OutcomeFailed
		res.Err = w.err
	case w.code != 0:
		res.Outcome = task.OutcomeFailed
		res.Err = fmt.Errorf("exit status %d", w.code)
	}
	if w.err != nil && res.Outcome != task.OutcomeNotStarted && res.Outcome != task.OutcomeFailed {
		res.Err = fmt.Errorf("%w (%v)", res.Err, w.err)
	}
	return res
}

// stop asks the launcher to end the run and waits for the agent to exit.
func (r *Runner) stop(proc launcher.Process, waited <-chan waitResult) waitResult {
	var stopErr error
	if err := proc.Stop(); err != nil {
		stopErr = fmt.Errorf("stop agent: %w", err)
	}
	select {
	case w := <-waited:
		if w.err == nil {
			w.err = stopErr
		}
		return w
	case <-time.After(r.cfg.StopGrace + stopWait):
		return waitResult{-1, errors.Join(stopErr, errors.New("the agent did not exit after the stop; it may still be running"))}
	}
}

// The agent's environment. The agent reads untrusted ticket text, so it never
// inherits ochell's own environment, which holds the webhook secrets and API
// keys: only the variables named in env_pass are copied from it.
func (r *Runner) inheritedEnv() []string {
	env := []string{}
	for _, name := range r.cfg.EnvPass {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// taskEnv is what ochell sets for the agent: ORCH_TASK_* and agent.env.
func (r *Runner) taskEnv(t *task.Task) []string {
	env := []string{
		"ORCH_TASK_ID=" + t.ID,
		"ORCH_TASK_SOURCE=" + t.Source,
		"ORCH_TASK_KEY=" + t.Key,
		"ORCH_TASK_URL=" + t.URL,
	}
	for k, v := range r.cfg.Env {
		env = append(env, k+"="+v)
	}
	return env
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(p)
	if over := b.buf.Len() - b.max; over > 0 {
		b.buf.Next(over)
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
