// Package runner queues tasks and launches the agent CLI for each of them.
//
// Exactly one agent process is started per task; any multi-agent work is
// managed by that agent. The command is executed directly (no shell) so
// ticket content can never be interpreted as shell syntax.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"ochell/internal/config"
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
		log.Error("agent failed", "exit", res.ExitCode, "err", res.Err, "duration", res.Duration, "log", res.LogFile)
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

// Run renders the prompt and executes the agent synchronously.
func (r *Runner) Run(ctx context.Context, t *task.Task) (res task.Result) {
	start := time.Now()
	res.ExitCode = -1
	defer func() { res.Duration = time.Since(start) }()

	var err error
	if t.Prompt, err = render(r.prompt, t); err != nil {
		res.Err = fmt.Errorf("render prompt: %w", err)
		return res
	}
	args := make([]string, 0, len(r.args))
	for _, a := range r.args {
		s, err := render(a, t)
		if err != nil {
			res.Err = fmt.Errorf("render args: %w", err)
			return res
		}
		args = append(args, s)
	}
	dir, err := render(r.workdir, t)
	if err != nil {
		res.Err = fmt.Errorf("render workdir: %w", err)
		return res
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		res.Err = fmt.Errorf("create workdir: %w", err)
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

	if r.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.cfg.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, r.cfg.Command, args...)
	cmd.Dir = dir
	cmd.WaitDelay = 10 * time.Second
	cmd.Env = append(os.Environ(),
		"ORCH_TASK_ID="+t.ID,
		"ORCH_TASK_SOURCE="+t.Source,
		"ORCH_TASK_KEY="+t.Key,
		"ORCH_TASK_URL="+t.URL,
	)
	for k, v := range r.cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if r.cfg.PromptVia == "stdin" {
		cmd.Stdin = strings.NewReader(t.Prompt)
	}
	tail := &tailBuffer{max: tailSize}
	out := io.MultiWriter(lf, tail)
	cmd.Stdout, cmd.Stderr = out, out

	err = cmd.Run()
	res.Tail = tail.String()
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		res.Err = fmt.Errorf("agent timed out after %s", r.cfg.Timeout)
	case err != nil:
		res.Err = err
	}
	fmt.Fprintf(lf, "\n# ---- exit=%d err=%v duration=%s ----\n", res.ExitCode, res.Err, time.Since(start))
	return res
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
