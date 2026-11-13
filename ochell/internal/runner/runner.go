// Package runner queues tasks and launches the agent CLI for each of them.
//
// Exactly one agent process is started per task; any multi-agent work is
// managed by that agent. The command is executed without a shell, so ticket
// content can never be interpreted as shell syntax. A launcher (package
// launcher) starts and stops the process.
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
	"ochell/internal/task"
)

var (
	ErrBusy      = errors.New("a task for this ticket is already queued or running")
	ErrQueueFull = errors.New("task queue is full")
	ErrStopped   = errors.New("runner is stopped")
)

const tailSize = 4096

type Runner struct {
	cfg      config.Agent
	log      *slog.Logger
	launcher launcher.Launcher
	prompt   *template.Template
	args     []*template.Template
	workdir  *template.Template
	queue    chan *task.Task
	mu       sync.Mutex
	inFlight map[string]bool
	stopped  bool
	wg       sync.WaitGroup
}

func New(cfg config.Agent, log *slog.Logger) (*Runner, error) {
	r := &Runner{cfg: cfg, log: log, inFlight: map[string]bool{}}
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
	size := cfg.QueueSize
	if size < 1 {
		size = 1
	}
	r.queue = make(chan *task.Task, size)
	return r, nil
}

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

func ticketKey(t *task.Task) string { return t.Source + ":" + t.Key }

// Submit queues a task. It never blocks.
func (r *Runner) Submit(t *task.Task) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	k := ticketKey(t)
	if r.inFlight[k] {
		return ErrBusy
	}
	select {
	case r.queue <- t:
		r.inFlight[k] = true
		return nil
	default:
		return ErrQueueFull
	}
}

// Start launches the worker pool. Workers exit when ctx is cancelled;
// cancelling ctx also terminates running agents.
func (r *Runner) Start(ctx context.Context) {
	n := max(r.cfg.MaxConcurrent, 1)
	for range n {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t := <-r.queue:
					r.handle(ctx, t)
				}
			}
		}()
	}
}

// Stop rejects new tasks and waits for workers to exit (after ctx passed to
// Start is cancelled).
func (r *Runner) Stop() {
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
	r.wg.Wait()
}

func (r *Runner) handle(ctx context.Context, t *task.Task) {
	defer func() {
		r.mu.Lock()
		delete(r.inFlight, ticketKey(t))
		r.mu.Unlock()
	}()
	log := r.log.With("task", t.ID, "source", t.Source, "key", t.Key)

	notifyCtx := context.WithoutCancel(ctx)
	if t.OnStart != nil {
		if err := t.OnStart(notifyCtx, t); err != nil {
			log.Warn("start notification failed", "err", err)
		}
	}
	res := r.Run(ctx, t)
	if res.Err != nil {
		log.Error("agent run did not succeed", "outcome", res.Outcome, "exit", res.ExitCode, "err", res.Err, "duration", res.Duration, "log", res.LogFile)
	} else {
		log.Info("agent finished", "duration", res.Duration, "log", res.LogFile)
	}
	if t.OnFinish != nil {
		if err := t.OnFinish(notifyCtx, t, res); err != nil {
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
// ctx stops the agent.
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
		res.Err = errors.New("the agent was stopped before it finished")
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
