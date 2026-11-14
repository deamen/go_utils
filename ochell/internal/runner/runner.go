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

	"ochell/internal/agent"
	"ochell/internal/config"
	"ochell/internal/launcher"
	"ochell/internal/result"
	"ochell/internal/store"
	"ochell/internal/task"
	"ochell/internal/ticket"
)

var (
	ErrBusy      = store.ErrBusy
	ErrQueueFull = store.ErrQueueFull
	ErrAttempts  = store.ErrAttempts
	ErrStopped   = errors.New("runner is stopped")
)

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
	adapter  agent.Adapter
	launcher launcher.Launcher
	prompt   *template.Template
	args     []*template.Template
	workdir  *template.Template
	// runDir is the absolute path of agent.run_dir.
	runDir  string
	ws      *workspace
	locks   ticketLocks
	mu      sync.Mutex
	stopped bool
	wg      sync.WaitGroup
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
	// The agent gets the path of its result file in its environment, and
	// runs in another directory.
	if r.runDir, err = filepath.Abs(cfg.RunDir); err != nil {
		return nil, fmt.Errorf("agent run_dir: %w", err)
	}
	if r.ws, err = newWorkspace(config.Workspace{Branch: "bot/{{.Key}}"}); err != nil {
		return nil, err
	}
	if r.adapter, err = agent.New(cfg); err != nil {
		return nil, err
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
// already has a queued or running task, ErrAttempts when the ticket has had
// max_attempts runs, and ErrQueueFull when queue_size tasks are waiting.
func (r *Runner) Submit(t *task.Task) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	if err := r.store.Enqueue(t, store.Limits{MaxQueued: max(r.cfg.QueueSize, 1), MaxAttempts: r.cfg.MaxAttempts}); err != nil {
		return err
	}
	r.wakeWorker()
	return nil
}

// Pause holds the queue: no new run starts until Resume. Running agents go
// on, and webhooks are still accepted and queued. The flag is in the store,
// so it is kept across a restart.
func (r *Runner) Pause() error {
	if err := r.store.SetPaused(true); err != nil {
		return err
	}
	r.log.Warn("paused: no new run starts until ochell is resumed")
	return nil
}

// Resume ends a pause.
func (r *Runner) Resume() error {
	if err := r.store.SetPaused(false); err != nil {
		return err
	}
	r.log.Info("resumed")
	r.wakeWorker()
	return nil
}

// Status is what ochell is doing right now.
type Status struct {
	Paused  bool `json:"paused"`
	Queued  int  `json:"queued"`
	Running int  `json:"running"`
}

func (r *Runner) Status() (Status, error) {
	var st Status
	var err error
	if st.Paused, err = r.store.Paused(); err != nil {
		return st, err
	}
	st.Queued, st.Running, err = r.store.Counts()
	return st, err
}

// ResetAttempts lets a ticket that used up its attempts be started again.
func (r *Runner) ResetAttempts(source, key string) error {
	if err := r.store.ResetAttempts(source, key); err != nil {
		return err
	}
	r.log.Info("attempts reset", "source", source, "key", key)
	return nil
}

// Hold records the ticket of t as waiting for a human, without starting
// anything. It returns ErrBusy when the ticket has a queued or running task.
func (r *Runner) Hold(t *task.Task, reason ticket.Reason) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	return r.store.Hold(t, reason)
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
	if held, err := r.store.Paused(); err == nil && held {
		r.log.Warn("ochell is paused: no run starts until it is resumed (ochell resume)")
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

	// One thing at a time in the ticket's working directory. If the
	// directory was removed since the task was claimed, the run must
	// prepare it again.
	defer r.locks.lock(t.Source, t.Key)()
	if tk, err := r.store.Ticket(t.Source, t.Key); err == nil && tk != nil {
		t.PreparedWorkspace, t.Workspace, t.AgentSession = tk.PreparedWorkspace, tk.Workspace, tk.AgentSession
	}

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

// promptView is what the prompt template sees: the task, and what ochell
// adds for this run.
type promptView struct {
	*task.Task
	// ResultFile is where the agent writes its result file.
	ResultFile string
	// ResultInstructions tells the agent to write it, and how.
	ResultInstructions string
	// RunContext says what only ochell knows about this run (runContext).
	// It is empty when there is nothing to say.
	RunContext string
}

// command renders the prompt and the arguments of a run, and asks the
// adapter for the command. With resume it continues the ticket's session,
// and the prompt says so; the adapter may answer agent.ErrNoResume.
func (r *Runner) command(t *task.Task, view promptView, resume bool) (agent.Command, error) {
	view.RunContext = runContext(t, resume)
	var err error
	if t.Prompt, err = render(r.prompt, view); err != nil {
		return agent.Command{}, fmt.Errorf("render prompt: %w", err)
	}
	args := make([]string, 0, len(r.args))
	for _, a := range r.args {
		s, err := render(a, r.argData(t))
		if err != nil {
			return agent.Command{}, fmt.Errorf("render args: %w", err)
		}
		args = append(args, s)
	}
	run := agent.Run{Args: args, Prompt: t.Prompt}
	if resume {
		return r.adapter.Resume(run, t.AgentSession)
	}
	return r.adapter.Start(run)
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

	// Each run has a directory of its own for its result file, so a file
	// of an earlier run is never taken for this one.
	runName := unsafeName.ReplaceAllString(t.ID, "_")
	runDir := filepath.Join(r.runDir, runName)
	resultFile := filepath.Join(runDir, result.FileName)

	dir, err := render(r.workdir, r.argData(t))
	if err != nil {
		res.Err = fmt.Errorf("render workdir: %w", err)
		return res
	}
	res.Workdir = dir
	if err := r.ws.check(dir); err != nil {
		res.Err = err
		return res
	}

	// The adapter says how this agent is called and reads what it prints;
	// the launcher runs it. A ticket that ran before, in the same working
	// directory, continues its session if the agent can do that. The
	// prompt tells the agent which of the two this is.
	view := promptView{Task: t, ResultFile: resultFile, ResultInstructions: result.Instructions}
	var cmd agent.Command
	err = agent.ErrNoResume
	if t.AgentSession != "" && t.Workspace == dir {
		cmd, err = r.command(t, view, true)
		res.Resumed = err == nil
	}
	if errors.Is(err, agent.ErrNoResume) {
		cmd, err = r.command(t, view, false)
	}
	if err != nil {
		res.Err = fmt.Errorf("build the agent command: %w", err)
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
	session := "new"
	if res.Resumed {
		session = "resumed " + t.AgentSession
	}
	fmt.Fprintf(lf, "# task=%s source=%s key=%s url=%s\n# command=%s (%d args) workdir=%s session=%s\n# prompt:\n%s\n",
		t.ID, t.Source, t.Key, t.URL, r.cfg.Command, len(cmd.Args), dir, session, t.Prompt)
	// signal is what the footer of the log says about the result file.
	signal := "none"
	defer func() {
		fmt.Fprintf(lf, "\n# ---- exit=%d outcome=%s result=%s err=%v duration=%s ----\n", res.ExitCode, res.Outcome, signal, res.Err, time.Since(start))
	}()

	// The workspace hooks come first. If one fails, the agent is not
	// started in a directory that is not ready.
	if err := r.prepare(ctx, t, dir, runName, lf); err != nil {
		res.Err = err
		if ctx.Err() != nil {
			res.Outcome = task.OutcomeStopped
		}
		return res
	}
	fmt.Fprintf(lf, "# ---- agent output ----\n")

	out := r.adapter.Output()
	spec := launcher.Spec{
		TaskID:    runName,
		Command:   r.cfg.Command,
		Args:      cmd.Args,
		Stdin:     cmd.Stdin,
		Dir:       dir,
		RunDir:    runDir,
		Env:       append(r.taskEnv(t), result.EnvVar+"="+resultFile),
		Inherited: r.inheritedEnv(),
		Output:    io.MultiWriter(lf, out),
		Timeout:   r.cfg.Timeout,
	}
	w, outcome := r.execute(ctx, spec)
	if outcome == task.OutcomeNotStarted {
		res.Err = w.err
		return res
	}
	res.Outcome = outcome
	rep := out.Report()
	res.Message, res.SessionID, res.CostUSD, res.Usage = rep.Message, rep.SessionID, rep.CostUSD, rep.Usage
	// What the agent says about its run. The file is read whenever the
	// agent ran, and stored; it decides the ticket's state only for a run
	// that ended by itself with status 0 (ticket.AfterRun).
	if f, err := result.Read(r.runDir, runName); err == nil {
		res.Signal, res.SignalMessage, res.PRURL, res.Branch = f.Status, f.Message, f.PRURL, f.Branch
		signal = string(f.Status)
	} else if !errors.Is(err, os.ErrNotExist) {
		signal = "invalid"
		r.log.Warn("the agent's result file cannot be used", "task", t.ID, "file", resultFile, "err", err)
	}
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
	// after_run follows every run in which the agent was started, but not
	// one that a shutdown cut short. It does not change how the run ended.
	if res.Outcome != task.OutcomeNotStarted && ctx.Err() == nil {
		if err := r.hook(ctx, "after_run", t, dir, runName, lf); err != nil {
			r.log.Warn("after_run hook failed", "task", t.ID, "err", err)
		}
	}
	return res
}

// execute starts what spec describes and waits for it to end. It stops it
// at spec.Timeout, and when ctx is done.
//
// Why it ended is decided here, from what ochell asked for. The exit code
// cannot tell: a unit that systemd stopped exits with 0, and one that hit
// its own time limit exits with 1 like a failed agent. The outcome is
// finished (it ended by itself, with any exit code), timed_out, stopped, or
// not_started with the reason in the error.
func (r *Runner) execute(ctx context.Context, spec launcher.Spec) (waitResult, task.Outcome) {
	proc, err := r.launcher.Start(spec)
	if err != nil {
		return waitResult{-1, err}, task.OutcomeNotStarted
	}
	waited := make(chan waitResult, 1)
	go func() {
		code, err := proc.Wait()
		waited <- waitResult{code, err}
	}()
	var timeout <-chan time.Time
	if spec.Timeout > 0 {
		timer := time.NewTimer(spec.Timeout)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case w := <-waited:
		return w, task.OutcomeFinished
	case <-timeout:
		return r.stop(proc, waited), task.OutcomeTimedOut
	case <-ctx.Done():
		return r.stop(proc, waited), task.OutcomeStopped
	}
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
	if t.Repo != "" {
		env = append(env, "ORCH_TASK_REPO="+t.Repo)
	}
	if branch := r.ws.view(t).Branch; branch != "" {
		env = append(env, "ORCH_TASK_BRANCH="+branch)
	}
	for k, v := range r.cfg.Env {
		env = append(env, k+"="+v)
	}
	return env
}
