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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"ochell/internal/agent"
	"ochell/internal/config"
	"ochell/internal/launcher"
	"ochell/internal/policy"
	"ochell/internal/result"
	"ochell/internal/store"
	"ochell/internal/task"
	"ochell/internal/ticket"
	"ochell/internal/workflow"
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

// ProgressNotifier is a Notifier that also wants to hear what the agent
// does while it runs.
type ProgressNotifier interface {
	// ToolUsed is called when the agent starts to use a tool. It is
	// called while the agent's output is being read, and must not block.
	ToolUsed(t *task.Task, tool, param string)
}

type Runner struct {
	cfg    config.Agent
	log    *slog.Logger
	store  *store.Store
	notify Notifier
	// progress is notify when it is a ProgressNotifier.
	progress ProgressNotifier
	adapter  agent.Adapter
	launcher launcher.Launcher
	// policy holds the risk tiers; the built-in one without a policy file.
	policy  *policy.Policy
	prompt  *template.Template
	args    []*template.Template
	workdir *template.Template
	// transient are agent.retry.patterns: what the output of a run that
	// failed for a temporary reason looks like.
	transient []*regexp.Regexp
	// runDir is the absolute path of agent.run_dir.
	runDir string
	// stateDir holds the home directories of the tickets, with the podman
	// launcher; empty with the others.
	stateDir string
	ws       *workspace
	locks    ticketLocks
	mu       sync.Mutex
	stopped  bool
	wg       sync.WaitGroup
	// What a stop from outside needs to know about the runs in progress,
	// by source and key (ticketKey). All three are guarded by mu.
	//
	// cancels ends the run of a ticket; stops says who asked for a stop
	// that has not taken effect yet; closing marks a ticket that the
	// tracker closed while it ran.
	cancels map[string]context.CancelFunc
	stops   map[string]string
	closing map[string]bool
	// retention says how long run logs are kept (retention.go), and backup
	// where the store is backed up (backup.go).
	retention config.Retention
	backup    config.Backup
	// followChecks says that ochell follows the checks of pull requests
	// (it has access to GitHub): a ticket whose run handed a pull request
	// over waits for them before it is in review.
	followChecks bool
	// wfCfg says what a repository's WORKFLOW.md may add, and wfSrc reads
	// the file; nil: no repository's file is looked at (workflow.go).
	wfCfg config.Workflow
	wfSrc WorkflowSource
	// levelMu makes a change of a class's level of autonomy one step: the
	// level is read, decided on and written under it (autonomy.go). It is
	// never held while mu is asked for.
	levelMu sync.Mutex
	// raised holds, for a ticket whose run is being stopped because the
	// ticket moved to a higher tier, that tier. Guarded by mu.
	raised map[string]string
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
	r := &Runner{cfg: cfg, log: log, store: st, policy: policy.Builtin(), wake: make(chan struct{}, 1), quit: make(chan struct{}),
		cancels: map[string]context.CancelFunc{}, stops: map[string]string{}, closing: map[string]bool{}, raised: map[string]string{}}
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
	for i, p := range cfg.Retry.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("agent retry.patterns[%d]: %w", i, err)
		}
		r.transient = append(r.transient, re)
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
	if cfg.Launcher == "podman" {
		if r.stateDir, err = filepath.Abs(cfg.Podman.StateDir); err != nil {
			return nil, fmt.Errorf("agent podman.state_dir: %w", err)
		}
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

// UsePolicy sets the policy with the risk tiers. Call it before Start.
// Without it the built-in policy holds.
//
// A policy with a budget needs an agent that can be kept to it. With any
// other agent the budget would silently be no limit, so that is refused.
func (r *Runner) UsePolicy(p *policy.Policy) error {
	holds := store.Holds{Paused: p.Paused, MaxRunsPerHour: p.Throttles.MaxRunsPerHour,
		MaxOpenPRsPerRepo: p.Throttles.MaxOpenPRsPerRepo, DailySpendUSD: p.Throttles.DailySpendUSD,
		MaxConcurrentPerRepo: p.Scheduling.MaxConcurrentPerRepo, MaxConcurrentPerTier: map[string]int{}}
	for _, t := range p.Tiers {
		if t.Paused {
			holds.PausedTiers = append(holds.PausedTiers, t.Name)
		}
		if t.MaxConcurrent > 0 {
			holds.MaxConcurrentPerTier[t.Name] = t.MaxConcurrent
		}
	}
	if holds.DailySpendUSD > 0 && !agent.LimitsBudget(r.adapter) {
		return fmt.Errorf("the policy sets throttles.daily_spend_usd, but agent.adapter %s reports no cost: use agent.adapter claude, or take the throttle out of the policy", r.cfg.Adapter)
	}
	r.store.SetHolds(holds)
	if !agent.LimitsBudget(r.adapter) {
		for _, t := range p.Tiers {
			if t.BudgetUSD > 0 {
				return fmt.Errorf("the policy sets budget_usd for the tier %s, but agent.adapter %s reports no cost and cannot stop a run at a limit: use agent.adapter claude, or take budget_usd out of the policy", t.Name, r.cfg.Adapter)
			}
			if t.MaxTurns > 0 {
				return fmt.Errorf("the policy sets max_turns for the tier %s, but agent.adapter %s cannot stop a run at a limit: use agent.adapter claude, or take max_turns out of the policy", t.Name, r.cfg.Adapter)
			}
		}
	}
	r.policy = p
	return nil
}

// FollowChecks says that the checks of pull requests are followed. Call
// it before Start.
func (r *Runner) FollowChecks(on bool) { r.followChecks = on }

// handOver looks at a run that ended with the work handed over (done).
//
// With the checks of pull requests followed, a ticket that has a pull
// request is not in review yet: it waits for the checks. And in a run that
// was started because the checks failed, "blocked" is the agent's word
// that it cannot fix them: the ticket then goes to review as it is, for a
// person to decide.
func (r *Runner) handOver(t *task.Task, res *task.Result) {
	if res.Outcome != task.OutcomeFinished || t.Phase == task.PhasePlan {
		return
	}
	if t.Cause == task.CauseChecks && res.Signal == result.Blocked {
		res.Signal = result.Done
		res.SignalMessage = "The checks of the pull request still fail, and the agent says that it cannot fix them: " + res.SignalMessage
		return
	}
	if r.followChecks && res.Signal == result.Done && (res.PRURL != "" || t.PRURL != "") {
		res.AwaitChecks = true
	}
}

// ToReview moves a ticket that waited for the checks of its pull request
// to review.
func (r *Runner) ToReview(source, key string) error {
	return r.store.ToReview(source, key)
}

// WakeForChecks queues a run of a ticket whose pull request failed its
// checks; t.Comment says what failed. It returns store.ErrNotChecking,
// ErrAttempts when the ticket has no attempt left, and ErrQueueFull.
func (r *Runner) WakeForChecks(t *task.Task) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	t.Cause = task.CauseChecks
	if err := r.store.WakeForChecks(t, store.Limits{MaxQueued: max(r.cfg.QueueSize, 1), MaxAttempts: r.cfg.MaxAttempts}); err != nil {
		return err
	}
	r.wakeWorker()
	return nil
}

// NotePullRequest records how far a pull request has been followed.
func (r *Runner) NotePullRequest(source, key, url, checkedSHA string, seenComment time.Time) error {
	return r.store.NotePullRequest(source, key, url, checkedSHA, seenComment)
}

// SetNotifier sets who is told about the runs. Call it before Start.
func (r *Runner) SetNotifier(n Notifier) {
	r.notify = n
	r.progress, _ = n.(ProgressNotifier)
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

// FollowUp queues a run of a ticket that ochell already knows, for a
// message from a person (t.Comment). It never blocks. It returns
// store.ErrUnknown for a ticket that ochell has never seen, and
// ErrQueueFull.
//
// When the ticket already has a queued or running task, the message is kept
// and delivered with the run that follows it; later is then true.
//
// addressed says that the person wrote to the agent itself (a Linear agent
// session). A comment on the ticket (Jira) is not addressed: it counts only
// while ochell holds the ticket, and gets store.ErrReleased otherwise.
//
// The attempt cap does not stop it: a person asked for this run, and the
// ticket's attempts count from here again.
func (r *Runner) FollowUp(t *task.Task, addressed bool) (later bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false, ErrStopped
	}
	t.Cause = task.CauseFollowUp
	if later, err = r.store.FollowUp(t, addressed, store.Limits{MaxQueued: max(r.cfg.QueueSize, 1)}); err != nil {
		return false, err
	}
	// A person may have sent the ticket back: the rate of its class is
	// looked at before the run starts, so that a demotion holds for it.
	r.checkLevels()
	r.wakeWorker()
	return later, nil
}

// Approve records that a person, named in by, approved the agent's plan
// for the ticket of t, and queues the run that carries it out, in the same
// agent session. Whether that person may approve is the caller's matter.
//
// It returns store.ErrNoPlan unless the ticket waits for a plan approval,
// store.ErrUnknown, and ErrQueueFull.
func (r *Runner) Approve(t *task.Task, by string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	t.Cause = task.CauseApproved
	if err := r.store.Approve(t, by, store.Limits{MaxQueued: max(r.cfg.QueueSize, 1)}); err != nil {
		return err
	}
	r.log.Info("plan approved", "source", t.Source, "key", t.Key, "by", by, "task", t.ID)
	r.wakeWorker()
	return nil
}

// OpenPullRequests returns the tracked pull requests that are open, of
// tickets that are neither done nor cancelled.
func (r *Runner) OpenPullRequests() ([]store.PullRequest, error) {
	return r.store.OpenPullRequests()
}

// SetPullRequest records what became of a tracked pull request.
func (r *Runner) SetPullRequest(source, key, url, state, closedBy, note string) error {
	return r.store.SetPullRequest(source, key, url, state, closedBy, note)
}

// Session returns the tracker session that the last run of a ticket
// reported to, or "".
func (r *Runner) Session(source, key string) (string, error) {
	t, err := r.store.LastTask(source, key)
	if err != nil || t == nil {
		return "", err
	}
	return t.TrackerSession, nil
}

// Assigner returns who last assigned a ticket to the bot, as the source
// named them, or "" when the source did not say. known is false for a
// ticket that ochell has never seen.
func (r *Runner) Assigner(source, key string) (assigner string, known bool, err error) {
	tk, err := r.store.Ticket(source, key)
	if err != nil || tk == nil {
		return "", false, err
	}
	return tk.Assigner, true, nil
}

// Tier returns the risk tier that ochell has recorded for a ticket, or ""
// when it has none: ochell has never seen the ticket, or saw it before
// there were tiers.
func (r *Runner) Tier(source, key string) (string, error) {
	tk, err := r.store.Ticket(source, key)
	if err != nil || tk == nil {
		return "", err
	}
	return tk.Tier, nil
}

// State returns the state of a ticket; ticket.None for one that ochell has
// never seen.
func (r *Runner) State(source, key string) (ticket.State, error) {
	tk, err := r.store.Ticket(source, key)
	if err != nil || tk == nil {
		return ticket.None, err
	}
	return tk.State, nil
}

// ActiveTickets returns the keys of the tickets of a source that have a
// queued or running task.
func (r *Runner) ActiveTickets(source string) ([]string, error) {
	return r.store.ActiveTickets(source)
}

// TicketOfSession returns the key of the ticket that reports to a tracker
// session, or "" when ochell knows none.
func (r *Runner) TicketOfSession(source, session string) (string, error) {
	return r.store.TicketOfSession(source, session)
}

func ticketKey(source, key string) string { return source + ":" + key }

// What Stop did.
type Stopped int

const (
	// StoppedRun: the agent was running, and is being stopped. The run
	// ends as cancelled a moment later.
	StoppedRun Stopped = iota + 1
	// StoppedQueued: the run was still queued, and will not start.
	StoppedQueued
	// Released: nothing was queued or running. The ticket is no longer
	// held: a comment on it starts nothing, until it is assigned again.
	Released
)

// Stop ends the work on a ticket for a person, named in by: it stops the
// running agent with all its processes, or takes the queued run out of the
// queue, or releases a ticket that waited. The ticket becomes cancelled and
// is not started again until it is assigned again. Messages that waited for
// its next run are dropped.
//
// The ticket is told what happened and by whom, through the notifier.
//
// It returns store.ErrUnknown for a ticket that ochell has never seen, and
// store.ErrReleased for one that is done or already cancelled.
func (r *Runner) Stop(source, key, by string) (Stopped, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return 0, ErrStopped
	}
	return r.stopLocked(source, key, by)
}

func (r *Runner) stopLocked(source, key, by string) (Stopped, error) {
	why := fmt.Errorf("the run was stopped by %s", by)
	queued, err := r.store.Stop(source, key, why)
	switch {
	case errors.Is(err, store.ErrBusy):
		// The agent is running. Its worker ends the run as cancelled; if
		// the worker has not got as far as starting it, it finds the
		// request when it does.
		k := ticketKey(source, key)
		if _, asked := r.stops[k]; !asked {
			r.stops[k] = by
		}
		if cancel := r.cancels[k]; cancel != nil {
			cancel()
		}
		r.log.Warn("stopping the run of a ticket", "source", source, "key", key, "by", by)
		return StoppedRun, nil
	case err != nil:
		return 0, err
	}
	did := Released
	res := task.Result{Outcome: task.OutcomeCancelled, ExitCode: -1, Err: fmt.Errorf("the ticket was released by %s", by)}
	t := queued
	if queued != nil {
		did, res.Err = StoppedQueued, why
	} else if t, err = r.store.LastTask(source, key); err != nil || t == nil {
		// Nothing to report to: the ticket never had a run.
		t = &task.Task{Source: source, Key: key}
	}
	r.log.Warn("ticket stopped", "source", source, "key", key, "by", by, "was_queued", queued != nil)
	r.wakeWorker()
	if r.notify != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			if err := r.notify.Finished(context.Background(), t, res); err != nil {
				r.log.Warn("stop notification failed", "source", source, "key", key, "err", err)
			}
		}()
	}
	return did, nil
}

// Pause holds the queue: no new run starts until Resume. Running agents go
// on, and webhooks are still accepted and queued. With a tier, only the
// tickets of that tier are held. The flag is in the store, so it is kept
// across a restart.
func (r *Runner) Pause(tier string) error {
	if tier == "" {
		if err := r.store.SetPaused(true); err != nil {
			return err
		}
		r.log.Warn("paused: no new run starts until ochell is resumed")
		return nil
	}
	if !r.policy.Has(tier) {
		return fmt.Errorf("%w: %q", ErrNoTier, tier)
	}
	if err := r.store.SetTierPaused(tier, true); err != nil {
		return err
	}
	r.log.Warn("tier paused: no run of a ticket in this tier starts until it is resumed", "tier", tier)
	return nil
}

// Resume ends a pause: of everything, or with a tier of that tier. A pause
// that the policy file sets is not ended by it.
func (r *Runner) Resume(tier string) error {
	if tier == "" {
		if err := r.store.SetPaused(false); err != nil {
			return err
		}
		r.log.Info("resumed")
	} else {
		if !r.policy.Has(tier) {
			return fmt.Errorf("%w: %q", ErrNoTier, tier)
		}
		if err := r.store.SetTierPaused(tier, false); err != nil {
			return err
		}
		r.log.Info("tier resumed", "tier", tier)
	}
	r.wakeWorker()
	return nil
}

// Status is what ochell is doing right now.
type Status struct {
	// Paused: nothing starts, because of a command or of the policy file.
	Paused  bool `json:"paused"`
	Queued  int  `json:"queued"`
	Running int  `json:"running"`
	// Holds says what keeps runs from starting besides a plain "ochell
	// pause", one line each: a pause in the policy file or of a tier,
	// each throttle that has reached its limit, each repository and tier
	// in which as many tickets run as may, and each ticket that a gate of
	// scheduling holds.
	Holds []string `json:"holds,omitempty"`
	// Workflows are the repositories whose WORKFLOW.md ochell has read.
	Workflows []WorkflowStatus `json:"workflows,omitempty"`
	// Autonomy are the classes of work with their level of autonomy, for
	// a policy that has levels.
	Autonomy []Class `json:"autonomy,omitempty"`
}

func (r *Runner) Status() (Status, error) {
	var st Status
	h, err := r.store.Holding()
	if err != nil {
		return st, err
	}
	st.Paused = h.Paused || h.PolicyPaused
	switch {
	case h.Paused && h.PolicyPaused:
		st.Holds = append(st.Holds, "paused by a command and by the policy file (paused: true)")
	case h.Paused:
		// The plain pause needs no line of its own.
	case h.PolicyPaused:
		st.Holds = append(st.Holds, "paused by the policy file (paused: true); change the file and restart to end it")
	}
	for _, t := range h.Tiers {
		st.Holds = append(st.Holds, fmt.Sprintf("tier %s is paused by a command; \"ochell resume --tier %s\" ends it", t, t))
	}
	for _, t := range h.PolicyTiers {
		st.Holds = append(st.Holds, fmt.Sprintf("tier %s is paused by the policy file", t))
	}
	for _, t := range h.Throttles {
		st.Holds = append(st.Holds, "throttle "+t)
	}
	max := r.policy.Throttles.MaxOpenPRsPerRepo
	repos, err := r.store.HeldByPRs(max)
	if err != nil {
		return st, err
	}
	for _, repo := range repos {
		st.Holds = append(st.Holds, fmt.Sprintf("throttle max_open_prs_per_repo: %d pull requests of the bot are open in %s; tickets that would open another wait", max, repo))
	}
	if err := r.scheduling(&st); err != nil {
		return st, err
	}
	if st.Workflows, err = r.workflows(); err != nil {
		return st, err
	}
	if st.Autonomy, err = r.classes(false); err != nil {
		return st, err
	}
	st.Queued, st.Running, err = r.store.Counts()
	return st, err
}

// maxHeldListed is how many held tickets the status names one by one.
const maxHeldListed = 20

// scheduling adds to st what scheduling holds back: the repositories and
// tiers that are full, and the tickets that wait at a gate.
func (r *Runner) scheduling(st *Status) error {
	max := r.policy.Scheduling.MaxConcurrentPerRepo
	repos, err := r.store.FullRepos(max)
	if err != nil {
		return err
	}
	for _, f := range repos {
		st.Holds = append(st.Holds, fmt.Sprintf("scheduling max_concurrent_per_repo: %d ticket(s) are running in %s, the limit is %d; %d queued ticket(s) of the repository wait", f.Running, f.Name, max, f.Waiting))
	}
	limits := map[string]int{}
	for _, t := range r.policy.Tiers {
		limits[t.Name] = t.MaxConcurrent
	}
	tiers, err := r.store.FullTiers(limits)
	if err != nil {
		return err
	}
	for _, f := range tiers {
		st.Holds = append(st.Holds, fmt.Sprintf("scheduling max_concurrent of the tier %s: %d ticket(s) are running, the limit is %d; %d queued ticket(s) of the tier wait", f.Name, f.Running, limits[f.Name], f.Waiting))
	}
	held, err := r.store.Held()
	if err != nil {
		return err
	}
	listed := 0
	for _, h := range held {
		// A ticket that was not looked at yet is about to be.
		if h.Hold == store.HoldPending {
			continue
		}
		if listed++; listed > maxHeldListed {
			continue
		}
		st.Holds = append(st.Holds, fmt.Sprintf("scheduling: %s %s waits: %s", h.Source, h.Key, h.Hold))
	}
	if listed > maxHeldListed {
		st.Holds = append(st.Holds, fmt.Sprintf("scheduling: %d more ticket(s) wait", listed-maxHeldListed))
	}
	return nil
}

// Held returns the tickets whose queued run scheduling keeps from
// starting.
func (r *Runner) Held() ([]store.Held, error) { return r.store.Held() }

// SetHold changes why scheduling holds the queued run of a ticket. With an
// empty hold the run may start, and a worker is told.
func (r *Runner) SetHold(source, key, hold string) (changed bool, err error) {
	changed, err = r.store.SetHold(source, key, hold)
	if err == nil && changed && hold == "" {
		r.log.Info("scheduling: the ticket no longer waits", "source", source, "key", key)
		r.wakeWorker()
	}
	return changed, err
}

// SetPriority records the priority that the tracker gives a ticket, as a
// rank: 1 is the most urgent; 0: none.
func (r *Runner) SetPriority(source, key string, priority int) error {
	return r.store.SetPriority(source, key, priority)
}

// Outcomes returns the outcome metrics per tier, for the period from
// since up to until.
func (r *Runner) Outcomes(since, until time.Time) ([]store.Outcomes, error) {
	return r.store.Outcomes(since, until)
}

// CostReport is what the tickets have cost.
type CostReport struct {
	// Total is over every run in the store, Today over the runs that
	// started since midnight UTC.
	Total, Today store.Cost
	// Tickets are the tickets that ochell touched last; the one ticket
	// when the report is about one.
	Tickets []TicketCost
	// Runs are the runs of that one ticket.
	Runs []store.RunCost
}

// TicketCost is what a ticket has cost, with the budget of its tier.
type TicketCost struct {
	store.TicketCost
	// BudgetUSD is the budget of the ticket's tier; 0: none.
	BudgetUSD float64
}

// maxCostTickets is how many tickets a report over all tickets lists.
const maxCostTickets = 50

// Cost reports what the runs have cost: for one ticket with each of its
// runs, or, with an empty key, for the tickets that ochell touched last. It
// returns store.ErrUnknown for a ticket that ochell has never seen.
func (r *Runner) Cost(source, key string) (*CostReport, error) {
	var rep CostReport
	var err error
	if rep.Total, err = r.store.TotalCost(time.Time{}); err != nil {
		return nil, err
	}
	if rep.Today, err = r.store.TotalCost(time.Now().UTC().Truncate(24 * time.Hour)); err != nil {
		return nil, err
	}
	with := func(c store.TicketCost) TicketCost {
		return TicketCost{TicketCost: c, BudgetUSD: r.policy.Tier(c.Tier).BudgetUSD}
	}
	if key == "" {
		list, err := r.store.TicketCosts(maxCostTickets)
		if err != nil {
			return nil, err
		}
		for _, c := range list {
			rep.Tickets = append(rep.Tickets, with(c))
		}
		return &rep, nil
	}
	c, err := r.store.TicketCost(source, key)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, store.ErrUnknown
	}
	rep.Tickets = []TicketCost{with(*c)}
	rep.Runs, err = r.store.RunCosts(source, key)
	return &rep, err
}

// ResetAttempts lets a ticket that used up its attempts or its budget be
// started again: both count from zero.
func (r *Runner) ResetAttempts(source, key string) error {
	if err := r.store.ResetAttempts(source, key); err != nil {
		return err
	}
	r.log.Info("attempts and budget reset", "source", source, "key", key)
	return nil
}

// ErrNoTier is returned for a tier that the policy does not have.
var ErrNoTier = errors.New("the policy has no such tier")

// SetTier puts a ticket under another risk tier, for an operator. It is the
// one way to lower a tier: nothing that happens on the ticket does. The
// next run of the ticket uses it. It returns ErrNoTier, and
// store.ErrUnknown for a ticket that ochell has never seen.
func (r *Runner) SetTier(source, key, tier string) error {
	if !r.policy.Has(tier) {
		return fmt.Errorf("%w: %q", ErrNoTier, tier)
	}
	if err := r.store.SetTier(source, key, tier); err != nil {
		return err
	}
	r.log.Info("tier set by an operator", "source", source, "key", key, "tier", tier)
	return nil
}

// TierChanged is called when the tracker shows that a ticket now belongs
// in a higher tier than the one ochell has for it, for example because a
// label was added. The ticket gets that tier.
//
// A run that is going on started under the lower tier. It is stopped, and
// the ticket waits for a human (an escalation): stopped is then true, and
// the ticket is told when the run has ended. A ticket without a running
// agent only gets the tier; its next run starts under it.
//
// It returns store.ErrUnknown for a ticket that ochell has never seen, and
// ErrNoTier.
func (r *Runner) TierChanged(source, key, tier string) (stopped bool, err error) {
	if !r.policy.Has(tier) {
		return false, fmt.Errorf("%w: %q", ErrNoTier, tier)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false, ErrStopped
	}
	tk, err := r.store.Ticket(source, key)
	if err != nil {
		return false, err
	}
	if tk == nil {
		return false, store.ErrUnknown
	}
	if tk.State != ticket.Running {
		r.log.Info("the ticket moved to a higher tier", "source", source, "key", key, "from", tk.Tier, "tier", tier)
		return false, r.store.SetTier(source, key, tier)
	}
	// The worker ends the run as an escalation and sets the tier; if it has
	// not got as far as starting the agent, it finds the request when it
	// does.
	k := ticketKey(source, key)
	r.raised[k] = tier
	if cancel := r.cancels[k]; cancel != nil {
		cancel()
	}
	r.log.Warn("stopping the run of a ticket that moved to a higher tier", "source", source, "key", key, "from", tk.Tier, "tier", tier)
	return true, nil
}

// escalate decides whether the run of t, which ended as res, was stopped
// by an escalation trigger, and acts on it: the ticket moves up one tier,
// and nothing is queued in the run's place. again is the run that ochell
// would start by itself, or nil. raisedTo is the tier that the ticket moved
// to in the tracker during the run, or "".
//
// The triggers: the budget or the turn limit of the tier; a temporary
// failure when the ticket has no attempt left for another try; a move to a
// higher tier during the run; and the agent's own word that it is not sure
// of its result or that the ticket is out of its scope.
func (r *Runner) escalate(t *task.Task, res *task.Result, again *store.Again, raisedTo string) *store.Again {
	to := r.policy.Next(t.Tier)
	switch {
	case res.Outcome == task.OutcomeCancelled:
		// A person stopped it; that is the end of it.
		return again
	case raisedTo != "":
		res.Escalation, to = task.EscalationTierChange, raisedTo
		res.Err = fmt.Errorf("the run was stopped: the ticket moved from the risk tier %s to %s while the agent was working on it", t.Tier, raisedTo)
	case res.Outcome == task.OutcomeOverBudget:
		res.Escalation = task.EscalationBudget
	case res.Outcome == task.OutcomeOverTurns:
		res.Escalation = task.EscalationTurns
	case again != nil && again.Cause == task.CauseRetry:
		if left, err := r.store.AttemptsLeft(t.Source, t.Key, again.MaxAttempts); err != nil || left {
			return again
		}
		res.Escalation = task.EscalationRetries
		res.Err = fmt.Errorf("the run failed with an error that looks temporary (%v), and the ticket has used its %d attempts", res.Err, again.MaxAttempts)
	case res.Outcome == task.OutcomeFinished && res.Signal == result.LowConfidence:
		res.Escalation = task.EscalationLowConfidence
	case res.Outcome == task.OutcomeFinished && res.Signal == result.OutOfScope:
		res.Escalation = task.EscalationOutOfScope
	default:
		return again
	}
	if to != t.Tier && r.policy.Higher(t.Tier, to) == to {
		if err := r.store.SetTier(t.Source, t.Key, to); err != nil {
			r.log.Error("cannot move the escalated ticket up a tier", "task", t.ID, "err", err)
		} else {
			res.TierBefore, res.TierAfter = t.Tier, to
		}
	}
	r.log.Warn("escalation: the ticket now waits for a human", "task", t.ID, "source", t.Source, "key", t.Key,
		"trigger", res.Escalation, "tier", t.Tier, "tier_now", to, "session", res.SessionID)
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

// again describes the run that takes the place of t.
func (r *Runner) again(t *task.Task, cause task.Cause) store.Again {
	return store.Again{ID: task.NewID(time.Now(), t.Source, t.Key), Cause: cause, MaxAttempts: r.cfg.MaxAttempts}
}

// Start launches the worker pool. Shutdown ends it. Tasks that were queued
// before a restart are run. A run that the restart cut short is closed, and
// another run of its ticket is queued in its place, with a note for the
// agent that it may have done part of the work (runContext). A ticket that
// has used up its attempts waits for a human instead.
func (r *Runner) Start() error {
	interrupted, err := r.store.Recover(func(t *task.Task) store.Again { return r.again(t, task.CauseRecovery) })
	if err != nil {
		return fmt.Errorf("recover the task store: %w", err)
	}
	for _, in := range interrupted {
		t := in.Task
		r.log.Warn("run was interrupted: ochell stopped while the agent was running", "task", t.ID, "source", t.Source, "key", t.Key, "queued_again", in.Next)
		// An agent that outlived the ochell that started it must not go on
		// working next to the run that takes its place.
		if err := r.launcher.Reap(unsafeName.ReplaceAllString(t.ID, "_")); err != nil {
			r.log.Warn("cannot make sure that the interrupted run has ended; its agent may still be running", "task", t.ID, "err", err)
		}
	}
	if len(interrupted) > 0 && r.notify != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for _, in := range interrupted {
				res := task.Result{Outcome: task.OutcomeInterrupted, ExitCode: -1, Err: store.ErrInterrupted}
				// A run that only delivers messages is not announced: the
				// ticket gets the error first, like any other.
				if in.Next != task.CauseFollowUp {
					res.Next = in.Next
				}
				if err := r.notify.Finished(context.Background(), in.Task, res); err != nil {
					r.log.Warn("finish notification failed", "task", in.Task.ID, "err", err)
				}
			}
		}()
	}
	if n, err := r.store.Active(); err == nil && n > 0 {
		r.log.Info("tasks queued before the restart will be run", "tasks", n)
	}
	if r.cfg.Watchdog.Repeats > 0 && !agent.ReportsTools(r.adapter) {
		// Better said than believed: nothing watches these runs.
		r.log.Warn("agent.watchdog.repeats is set, but this agent adapter reports no tool calls: the watchdog sees nothing and stops no run (agent.stall_timeout still stops a silent one)", "adapter", r.cfg.Adapter)
	}
	if st, err := r.Status(); err == nil {
		if st.Paused {
			r.log.Warn("ochell is paused: no run starts until it is resumed (ochell resume)")
		}
		for _, h := range st.Holds {
			r.log.Warn("runs are held back: " + h)
		}
	}

	if r.retention.Interval > 0 {
		r.wg.Add(1)
		go r.runRetention()
	}
	if r.backup.Dir != "" && r.backup.Interval > 0 {
		r.wg.Add(1)
		go r.runBackup()
	}
	if r.policy.Autonomy.Enabled() {
		r.wg.Add(1)
		go r.runAutonomy()
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
// A run that the shutdown stops is queued again, and runs after the restart
// with the recovery note.
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
	log := r.log.With("task", t.ID, "source", t.Source, "key", t.Key, "attempt", t.Attempt, "tier", t.Tier)

	// One thing at a time in the ticket's working directory. If the
	// directory was removed since the task was claimed, the run must
	// prepare it again.
	defer r.locks.lock(t.Source, t.Key)()
	if tk, err := r.store.Ticket(t.Source, t.Key); err == nil && tk != nil {
		t.PreparedWorkspace, t.Workspace, t.AgentSession = tk.PreparedWorkspace, tk.Workspace, tk.AgentSession
	}

	notifyCtx := context.WithoutCancel(ctx)
	// A stop from outside ends this run alone.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	k := ticketKey(t.Source, t.Key)
	r.mu.Lock()
	r.cancels[k] = cancel
	if _, asked := r.stops[k]; asked {
		// The stop came between the claim and now.
		cancel()
	}
	if _, moved := r.raised[k]; moved {
		cancel()
	}
	r.mu.Unlock()

	// What holds for this run: the ticket's tier, held back by the level of
	// autonomy that its class has now, and narrowed by the WORKFLOW.md of
	// its repository as the default branch has it now.
	t.Autonomy, _ = r.levelOf(r.policy.Tier(t.Tier).Name)
	if t.Autonomy != "" {
		log = log.With("autonomy", t.Autonomy)
	}
	wf := r.flow(ctx, t, log)
	// A ticket whose tier requires an approved plan, and has none, gets a
	// run that only plans. At the level observe that is every ticket.
	if wf.Tier.PlanGate == policy.PlanGateRequired && !t.PlanApproved {
		t.Phase = task.PhasePlan
	}
	// A ticket that has used up the budget of its tier is not started, by
	// whatever asked for this run. Otherwise the run gets what is left.
	var res task.Result
	if spent, budget, over := r.budget(t, wf.Tier, log); over {
		res = task.Result{Outcome: task.OutcomeOverBudget, ExitCode: -1,
			Err: fmt.Errorf("the run was not started: the ticket has cost %s of its budget of %s (tier %s)", usd(spent), usd(budget), t.Tier)}
	} else {
		if r.notify != nil && ctx.Err() == nil {
			if err := r.notify.Started(notifyCtx, t); err != nil {
				log.Warn("start notification failed", "err", err)
			}
		}
		res = r.run(ctx, t, wf)
	}
	res.Workflow, res.Autonomy = wf.version, t.Autonomy
	r.mu.Lock()
	by, stopped := r.stops[k]
	closed := r.closing[k]
	raisedTo := r.raised[k]
	delete(r.cancels, k)
	delete(r.stops, k)
	delete(r.closing, k)
	delete(r.raised, k)
	r.mu.Unlock()
	if stopped {
		// A person stopped it, which also holds when the run ended by
		// itself in the same moment: the ticket is cancelled.
		res.Outcome, res.Err = task.OutcomeCancelled, fmt.Errorf("the run was stopped by %s", by)
	}
	if res.Err != nil {
		log.Error("agent run did not succeed", "outcome", res.Outcome, "exit", res.ExitCode, "err", res.Err, "duration", res.Duration, "log", res.LogFile)
	} else {
		log.Info("agent finished", "duration", res.Duration, "log", res.LogFile)
	}
	// Record the end before telling the ticket, so the ticket is free for
	// a new run by the time someone reads the answer.
	var again *store.Again
	if a, ok := r.next(t, res); ok {
		again = &a
	}
	r.handOver(t, &res)
	// An escalation trigger stops the ticket here, before anything goes on.
	again = r.escalate(t, &res, again, raisedTo)
	next, err := r.store.FinishAndQueue(t.ID, res, again)
	switch {
	case err != nil:
		log.Error("cannot record the end of the run", "err", err)
	case next == task.CauseFollowUp:
		// Messages from people arrived during the run. The ticket gets the
		// result of this run as usual, and then the run that delivers them.
		log.Info("the ticket is queued again: messages arrived during the run")
	case next != "":
		res.Next, res.NextAt = again.Cause, again.NotBefore
		log.Info("the ticket is queued again", "cause", again.Cause, "run", again.ID, "not_before", again.NotBefore)
		if wait := time.Until(again.NotBefore); wait > 0 {
			// An idle worker looks at the queue when the wait is over.
			time.AfterFunc(wait+10*time.Millisecond, r.wakeWorker)
		}
	}
	// The run may have handed over a pull request, or delivered a message
	// that sent the ticket back: the rate of its class has changed.
	r.checkLevels()
	if r.notify != nil {
		if err := r.notify.Finished(notifyCtx, t, res); err != nil {
			log.Warn("finish notification failed", "err", err)
		}
	}
	if closed {
		// The tracker closed the ticket while it ran: now that the run has
		// ended, the ticket is done and its working directory can go.
		if err := r.Closed(t.Source, t.Key); err != nil && !errors.Is(err, ErrStopped) {
			log.Warn("cannot record that the ticket was closed", "err", err)
		}
	}
}

// phaseName is how the log names the phase of a run.
func phaseName(p task.Phase) string {
	if p == task.PhaseWork {
		return "work"
	}
	return string(p)
}

// usd writes an amount of money for a person.
func usd(v float64) string { return fmt.Sprintf("%.2f USD", v) }

// budget sets the limits of the run of t from the ticket's tier:
// t.MaxTurns, and t.BudgetUSD, which is what the ticket has left of the
// tier's budget. over says that nothing is left.
//
// tier is the ticket's tier as it holds for this run. A repository's
// WORKFLOW.md can have lowered its turns; the budget is the policy's alone.
func (r *Runner) budget(t *task.Task, tier policy.Tier, log *slog.Logger) (spent, budget float64, over bool) {
	t.MaxTurns = tier.MaxTurns
	budget = tier.BudgetUSD
	if budget <= 0 {
		return 0, 0, false
	}
	cost, err := r.store.TicketCost(t.Source, t.Key)
	if err != nil || cost == nil {
		// Not knowing what was spent must not open the budget.
		log.Error("cannot read what the ticket has cost; the run is not started", "err", err)
		return 0, budget, true
	}
	spent = cost.SinceResetUSD
	if spent >= budget {
		return spent, budget, true
	}
	t.BudgetUSD = budget - spent
	return spent, budget, false
}

// next says whether ochell itself starts the ticket of t again after a run
// that ended as res did, and describes that run:
//   - a run that a shutdown stopped goes on after the restart;
//   - a run that stalled, or that failed for a temporary reason (a rate
//     limit, an error of the model's API), is tried again after a wait.
//
// A failure of the task itself is not retried, and neither is a run that
// the watchdog stopped: it would go round in the same circle. Whether the ticket still has
// an attempt left is decided by the store.
func (r *Runner) next(t *task.Task, res task.Result) (store.Again, bool) {
	switch {
	case res.Outcome == task.OutcomeStopped:
		return r.again(t, task.CauseRecovery), true
	case res.Outcome == task.OutcomeStalled:
		again := r.again(t, task.CauseStalled)
		again.NotBefore = time.Now().Add(r.backoff(t.Attempt))
		return again, true
	case r.isTransient(res):
		again := r.again(t, task.CauseRetry)
		again.NotBefore = time.Now().Add(r.backoff(t.Attempt))
		return again, true
	}
	return store.Again{}, false
}

// isTransient reports whether a run failed for a reason outside the ticket
// that may be gone a little later. Only the configured patterns say so.
func (r *Runner) isTransient(res task.Result) bool {
	if res.Outcome != task.OutcomeFailed {
		return false
	}
	for _, re := range r.transient {
		if re.MatchString(res.Message) {
			return true
		}
	}
	return false
}

// backoff is the wait before the run that follows the given attempt of a
// ticket: agent.retry.backoff after the first, doubled with each further
// one, up to max_backoff.
func (r *Runner) backoff(attempt int) time.Duration {
	d, limit := r.cfg.Retry.Backoff, r.cfg.Retry.MaxBackoff
	for i := 1; i < attempt && d < limit; i++ {
		d *= 2
	}
	return max(min(d, limit), 0)
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
//
// prompt is the template of the run: the host's, or that of the
// repository's WORKFLOW.md.
func (r *Runner) command(t *task.Task, prompt *template.Template, view promptView, resume bool) (agent.Command, error) {
	view.RunContext = runContext(t, resume)
	var err error
	if t.Prompt, err = render(prompt, view); err != nil {
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
	run := agent.Run{Args: args, Prompt: t.Prompt, BudgetUSD: t.BudgetUSD, MaxTurns: t.MaxTurns}
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
	return r.run(ctx, t, r.flow(ctx, t, r.log))
}

// run is Run under what wf says holds for the run.
func (r *Runner) run(ctx context.Context, t *task.Task, wf *flow) (res task.Result) {
	start := time.Now()
	res.ExitCode = -1
	res.Outcome = task.OutcomeNotStarted
	res.Phase = t.Phase
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
	prompt := r.prompt
	if wf.prompt != nil {
		prompt = wf.prompt
	}
	var cmd agent.Command
	err = agent.ErrNoResume
	if t.AgentSession != "" && t.Workspace == dir {
		cmd, err = r.command(t, prompt, view, true)
		res.Resumed = err == nil
	}
	if errors.Is(err, agent.ErrNoResume) {
		cmd, err = r.command(t, prompt, view, false)
	}
	if err != nil {
		res.Err = fmt.Errorf("build the agent command: %w", err)
		return res
	}
	// For the audit record: which prompt this run was given, without
	// keeping the prompt itself in the store.
	sum := sha256.Sum256([]byte(t.Prompt))
	res.PromptHash = hex.EncodeToString(sum[:])

	if err := os.MkdirAll(r.cfg.LogDir, 0o750); err != nil {
		res.Err = fmt.Errorf("create log dir: %w", err)
		return res
	}
	res.LogFile = filepath.Join(r.cfg.LogDir, unsafeName.ReplaceAllString(t.ID, "_")+".log")
	file, err := os.OpenFile(res.LogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		res.Err = fmt.Errorf("open log: %w", err)
		return res
	}
	defer file.Close()
	session := "new"
	if res.Resumed {
		session = "resumed " + t.AgentSession
	}
	fmt.Fprintf(file, "# task=%s source=%s key=%s url=%s tier=%s phase=%s\n# command=%s (%d args) workdir=%s session=%s\n",
		t.ID, t.Source, t.Key, t.URL, t.Tier, phaseName(t.Phase), r.cfg.Command, len(cmd.Args), dir, session)
	if t.Autonomy != "" {
		fmt.Fprintf(file, "# autonomy=%s (the level of the tier %s)\n", t.Autonomy, t.Tier)
	}
	if wf.version != "" {
		fmt.Fprintf(file, "# workflow=%s (%s of %s, from its default branch)\n", wf.version, workflow.FileName, t.Repo)
	}
	for _, note := range wf.notes {
		fmt.Fprintf(file, "# workflow: %s\n", note)
	}
	fmt.Fprintf(file, "# prompt:\n%s\n", t.Prompt)
	// signal is what the footer of the log says about the result file.
	signal := "none"
	defer func() {
		fmt.Fprintf(file, "\n# ---- exit=%d outcome=%s result=%s err=%v duration=%s ----\n", res.ExitCode, res.Outcome, signal, res.Err, time.Since(start))
		// After the footer, which the harness and people look for at the
		// end of the run's own part.
		u := res.Usage
		fmt.Fprintf(file, "# cost_usd=%.6f tokens: input=%d output=%d cache_read=%d cache_write=%d\n", res.CostUSD, u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	}()

	// The workspace hooks come first. If one fails, the agent is not
	// started in a directory that is not ready.
	if err := r.prepare(ctx, t, dir, runName, file, wf); err != nil {
		res.Err = err
		if ctx.Err() != nil {
			res.Outcome = task.OutcomeStopped
		}
		return res
	}
	fmt.Fprintf(file, "# ---- agent output ----\n")

	// The session is recorded as soon as the agent names it, not only at
	// the end: if ochell does not live to see the end of this run, the run
	// that takes its place continues in the same session.
	// The watchdog sees the same tool calls, and stops a run that goes
	// round in a circle.
	dog := newWatchdog(r.cfg.Watchdog.Repeats)
	out := r.adapter.Output(func(ev agent.Event) {
		if ev.Tool != "" {
			if r.progress != nil {
				r.progress.ToolUsed(t, ev.Tool, ev.Param)
			}
			dog.observe(toolCall{id: ev.Call, tool: ev.Tool, param: ev.Param})
		}
		if ev.SessionID == "" {
			return
		}
		if err := r.store.NoteSession(t.Source, t.Key, ev.SessionID, dir); err != nil {
			r.log.Warn("cannot record the agent session of the running task", "task", t.ID, "err", err)
		}
	})
	spec := launcher.Spec{
		TaskID:    runName,
		Command:   r.cfg.Command,
		Args:      cmd.Args,
		Stdin:     cmd.Stdin,
		Dir:       dir,
		RunDir:    runDir,
		Env:       append(r.taskEnv(t), result.EnvVar+"="+resultFile),
		Inherited: r.inheritedEnv(),
		Home:      r.home(t.Source, t.Key),
		Output:    io.MultiWriter(file, out),
		Timeout:   r.cfg.Timeout,
	}
	w, outcome := r.execute(ctx, spec, r.cfg.StallTimeout, dog.stopped())
	if outcome == task.OutcomeNotStarted {
		res.Err = w.err
		return res
	}
	res.Outcome = outcome
	rep := out.Report()
	res.Message, res.SessionID, res.CostUSD, res.Usage = rep.Message, rep.SessionID, rep.CostUSD, rep.Usage
	if rep.CostIsSessionTotal {
		// The agent reports what its session has cost so far. What this
		// run cost is the part that came on top of the earlier runs in
		// the same session.
		res.SessionCostUSD = rep.CostUSD
		if res.Resumed && rep.SessionID == t.AgentSession {
			before, err := r.store.SessionCost(t.Source, t.Key, t.AgentSession)
			if err != nil {
				r.log.Warn("cannot read what the session cost before this run; the run is charged the session's total", "task", t.ID, "err", err)
			} else if before <= rep.CostUSD {
				res.CostUSD = rep.CostUSD - before
			}
		}
	}
	res.AgentError = rep.Failed
	// What the agent says about its run. The file is read whenever the
	// agent ran, and stored; it decides the ticket's state only for a run
	// that ended by itself with status 0 (ticket.AfterRun).
	if f, err := result.Read(r.runDir, runName); err == nil {
		res.Signal, res.SignalMessage, res.PRURL, res.Branch = f.Status, f.Message, f.PRURL, f.Branch
		signal = string(f.Status)
		if t.Phase == task.PhasePlan && res.Signal == result.Done {
			// The run was for a plan only. Whatever the agent calls it,
			// what it handed over waits for an approval.
			res.Signal = result.Plan
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		signal = "invalid"
		r.log.Warn("the agent's result file cannot be used", "task", t.ID, "file", resultFile, "err", err)
	}
	res.ExitCode = w.code
	switch {
	case res.Outcome == task.OutcomeTimedOut:
		res.Err = fmt.Errorf("agent timed out after %s", r.cfg.Timeout)
	case res.Outcome == task.OutcomeStalled:
		res.Err = fmt.Errorf("the agent wrote no output for %s and was stopped", r.cfg.StallTimeout)
	case res.Outcome == task.OutcomeNoProgress:
		res.Err = fmt.Errorf("the agent made no progress and was stopped: %s", dog.reason())
		r.log.Warn("watchdog: the run made no progress and was stopped; the ticket now waits for a human", "task", t.ID, "source", t.Source, "key", t.Key,
			"seen", dog.reason(), "session", res.SessionID)
	case res.Outcome == task.OutcomeStopped:
		res.Err = errors.New("the agent was stopped because ochell is shutting down")
	case errors.Is(w.err, launcher.ErrNotStarted):
		res.Outcome = task.OutcomeNotStarted
		res.Err = w.err
	case rep.OverBudget:
		// The agent CLI stopped at the limit that ochell gave it.
		res.Outcome = task.OutcomeOverBudget
		res.Err = fmt.Errorf("the run was stopped: it used up what the ticket had left of its budget (%s; tier %s)", usd(t.BudgetUSD), t.Tier)
	case rep.OverTurns:
		res.Outcome = task.OutcomeOverTurns
		res.Err = fmt.Errorf("the run was stopped: it reached the limit of %d turns of the tier %s", t.MaxTurns, t.Tier)
		if t.MaxTurns != r.policy.Tier(t.Tier).MaxTurns {
			res.Err = fmt.Errorf("the run was stopped: it reached the limit of %d turns that the %s of the repository sets (tier %s)", t.MaxTurns, workflow.FileName, t.Tier)
		}
	case w.err != nil:
		res.Outcome = task.OutcomeFailed
		res.Err = w.err
	case w.code != 0:
		res.Outcome = task.OutcomeFailed
		res.Err = fmt.Errorf("exit status %d", w.code)
	case res.AgentError:
		// The agent exited with status 0 and says itself that it failed.
		res.Outcome = task.OutcomeFailed
		res.Err = errors.New("the agent reported an error")
	}
	if w.err != nil && res.Outcome != task.OutcomeNotStarted && res.Outcome != task.OutcomeFailed {
		res.Err = fmt.Errorf("%w (%v)", res.Err, w.err)
	}
	// after_run follows every run in which the agent was started, but not
	// one that a shutdown cut short. It does not change how the run ended.
	if res.Outcome != task.OutcomeNotStarted && ctx.Err() == nil {
		if err := r.hooks(ctx, "after_run", t, dir, runName, file, wf); err != nil {
			r.log.Warn("after_run hook failed", "task", t.ID, "err", err)
		}
	}
	return res
}

// lastWrite notes when something was last written to the writer behind it.
type lastWrite struct {
	w  io.Writer
	at atomic.Int64 // unix nanoseconds
}

func (l *lastWrite) Write(p []byte) (int, error) {
	l.at.Store(time.Now().UnixNano())
	return l.w.Write(p)
}

func (l *lastWrite) idle() time.Duration {
	return time.Since(time.Unix(0, l.at.Load()))
}

// execute starts what spec describes and waits for it to end. It stops it
// at spec.Timeout, when ctx is done, with stall set, when it has written
// no output for that long, and when noProgress is closed (the watchdog of
// the run; nil: there is none).
//
// Why it ended is decided here, from what ochell asked for. The exit code
// cannot tell: a unit that systemd stopped exits with 0, and one that hit
// its own time limit exits with 1 like a failed agent. The outcome is
// finished (it ended by itself, with any exit code), timed_out, stalled,
// no_progress, stopped, or not_started with the reason in the error.
func (r *Runner) execute(ctx context.Context, spec launcher.Spec, stall time.Duration, noProgress <-chan struct{}) (waitResult, task.Outcome) {
	var silent <-chan time.Time
	var out *lastWrite
	if stall > 0 {
		out = &lastWrite{w: spec.Output}
		out.at.Store(time.Now().UnixNano())
		spec.Output = out
		tick := time.NewTicker(max(stall/10, 10*time.Millisecond))
		defer tick.Stop()
		silent = tick.C
	}
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
	for {
		select {
		case w := <-waited:
			return w, task.OutcomeFinished
		case <-timeout:
			return r.stop(proc, waited), task.OutcomeTimedOut
		case <-ctx.Done():
			return r.stop(proc, waited), task.OutcomeStopped
		case <-noProgress:
			return r.stop(proc, waited), task.OutcomeNoProgress
		case <-silent:
			if out.idle() >= stall {
				return r.stop(proc, waited), task.OutcomeStalled
			}
		}
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
	if t.Tier != "" {
		env = append(env, "ORCH_TASK_TIER="+t.Tier)
	}
	if t.Autonomy != "" {
		env = append(env, "ORCH_TASK_AUTONOMY="+t.Autonomy)
	}
	if branch := r.ws.view(t).Branch; branch != "" {
		env = append(env, "ORCH_TASK_BRANCH="+branch)
	}
	for k, v := range r.cfg.Env {
		env = append(env, k+"="+v)
	}
	return env
}
