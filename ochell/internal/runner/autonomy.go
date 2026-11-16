package runner

import (
	"errors"
	"fmt"
	"time"

	"ochell/internal/policy"
	"ochell/internal/store"
)

// Graduated autonomy: every class of work (the tickets of one tier) has a
// level, which holds back what its tier allows (policy.Narrow). An operator
// raises the level, one step at a time, with a command on the admin
// channel. ochell lowers it by itself when people send back too large a
// share of the class's pull requests, and when a guardrail outside ochell
// flags a run. Every change is recorded with who decided it and the
// numbers of the class at that moment.
//
// A change holds for the runs that start after it. Nothing here stops a
// run, moves a ticket to another tier or changes a budget.

// ByOchell is who decided a demotion that nobody decided.
const ByOchell = "ochell itself"

// autonomyInterval is how often ochell looks at the rates of the classes
// without a reason to. A follow-up and the end of a run make it look at
// once; the interval is for a window that has moved on.
const autonomyInterval = 15 * time.Minute

var (
	// ErrNoLevels: the policy has no autonomy section.
	ErrNoLevels = errors.New("the policy has no levels of autonomy (autonomy.start_level)")
	// ErrTopLevel: the class has the highest level it can have.
	ErrTopLevel = errors.New("the class has the highest level it can have")
	// ErrLowestLevel: the class is at the lowest level.
	ErrLowestLevel = errors.New("the class is at the lowest level")
)

// Class is one class of work and its level of autonomy.
type Class struct {
	// Tier is the name of the tier whose tickets are the class.
	Tier  string `json:"tier"`
	Level string `json:"level"`
	// Since is when the class got this level, By who decided it and
	// Reason why. They are empty for a class whose level nobody has
	// changed: it has the start level of the policy file.
	Since  *time.Time `json:"since,omitempty"`
	By     string     `json:"by,omitempty"`
	Reason string     `json:"reason,omitempty"`
	// Record is the numbers of the class under its present level, within
	// the window of the policy. It is what a promotion is decided on, and
	// what ochell demotes on. Only Autonomy sets it.
	Record *store.Record `json:"record,omitempty"`
}

// levelOf returns the level in force for the class of a tier, and the last
// change of it, if there was one. The level is empty when the policy has
// no levels.
//
// Not knowing the level must not give a class more autonomy: when the
// store cannot be read, the class counts as at the lowest level.
func (r *Runner) levelOf(tier string) (string, *store.LevelChange) {
	if !r.policy.Autonomy.Enabled() {
		return "", nil
	}
	last, err := r.store.Level(tier)
	if err != nil {
		r.log.Error("cannot read the level of autonomy; the lowest level holds", "tier", tier, "err", err)
		return policy.LevelObserve, nil
	}
	if last == nil {
		return r.policy.Level(tier, ""), nil
	}
	return r.policy.Level(tier, last.To), last
}

// record returns the numbers of a class under its present level: of the
// window of the policy, the part since the level last changed. So a class
// earns its record anew at every level, and one bad stretch takes one
// level away, not all of them.
func (r *Runner) record(tier string, last *store.LevelChange, now time.Time) (store.Record, error) {
	since := now.Add(-r.policy.Autonomy.Demote.Window)
	if last != nil && last.At.After(since) {
		since = last.At
	}
	return r.store.RecordOf(tier, since, now)
}

// classes returns the classes of work with their levels; with records also
// their numbers.
func (r *Runner) classes(records bool) ([]Class, error) {
	if !r.policy.Autonomy.Enabled() {
		return nil, nil
	}
	now := time.Now()
	var out []Class
	for _, t := range r.policy.Tiers {
		level, last := r.levelOf(t.Name)
		c := Class{Tier: t.Name, Level: level}
		if last != nil {
			c.Since, c.By, c.Reason = &last.At, last.By, last.Reason
		}
		if records {
			rec, err := r.record(t.Name, last, now)
			if err != nil {
				return nil, err
			}
			c.Record = &rec
		}
		out = append(out, c)
	}
	return out, nil
}

// maxChangesListed is how many changes of levels Autonomy returns.
const maxChangesListed = 20

// Autonomy returns the classes of work with their levels and their
// numbers, and the last changes of levels, the newest first. It returns
// ErrNoLevels for a policy without levels.
func (r *Runner) Autonomy() ([]Class, []store.LevelChange, error) {
	if !r.policy.Autonomy.Enabled() {
		return nil, nil, ErrNoLevels
	}
	classes, err := r.classes(true)
	if err != nil {
		return nil, nil, err
	}
	changes, err := r.store.LevelChanges(maxChangesListed)
	return classes, changes, err
}

// Promote raises the class of a tier by one level, for the operator named
// in by. It is the one way up: nothing on a ticket or in a repository
// promotes a class. The decision is recorded with the numbers of the class
// at this moment.
//
// It returns ErrNoLevels, ErrNoTier, and ErrTopLevel with the reason for a
// class that can go no higher.
func (r *Runner) Promote(tier, by, reason string) (store.LevelChange, error) {
	return r.step(tier, by, reason, true)
}

// Demote lowers the class of a tier by one level, for the operator named
// in by. It returns ErrNoLevels, ErrNoTier and ErrLowestLevel.
func (r *Runner) Demote(tier, by, reason string) (store.LevelChange, error) {
	return r.step(tier, by, reason, false)
}

func (r *Runner) step(tier, by, reason string, up bool) (store.LevelChange, error) {
	if !r.policy.Autonomy.Enabled() {
		return store.LevelChange{}, ErrNoLevels
	}
	if !r.policy.Has(tier) {
		return store.LevelChange{}, fmt.Errorf("%w: %q", ErrNoTier, tier)
	}
	r.levelMu.Lock()
	defer r.levelMu.Unlock()
	level, last := r.levelOf(tier)
	to := policy.LevelBelow(level)
	if up {
		to = policy.LevelAbove(level)
		if level == r.policy.MaxLevel(tier) {
			why := "it is the highest level"
			if level != policy.LevelAutoMerge {
				why = fmt.Sprintf("%s is for the lowest tier of the policy (%s) alone, and only when that tier sets auto_merge: %s",
					policy.LevelAutoMerge, r.policy.Tiers[0].Name, policy.AutoMergeAfterCI)
			}
			return store.LevelChange{}, fmt.Errorf("%w: the tier %s is at %s; %s", ErrTopLevel, tier, level, why)
		}
	}
	if to == level {
		return store.LevelChange{}, fmt.Errorf("%w: the tier %s is at %s", ErrLowestLevel, tier, level)
	}
	rec, err := r.record(tier, last, time.Now())
	if err != nil {
		return store.LevelChange{}, err
	}
	c, err := r.store.ChangeLevel(store.LevelChange{Class: tier, From: level, To: to, By: by, Reason: oneLine(reason), Record: rec})
	if err != nil {
		return c, err
	}
	r.log.Warn("autonomy: the level of a class was changed by an operator", "tier", tier, "from", level, "to", to, "by", by, "reason", c.Reason,
		"pull_requests", rec.PullRequests, "sent_back", rec.SentBack)
	return c, nil
}

// Flag records that a guardrail outside ochell flagged the work on a
// ticket, and lowers the class of the ticket (its tier) by one level. by
// names who ran the command, and reason is what the guardrail found. The
// flag is recorded with the ticket's last run that started. The ticket
// itself is not touched: its run goes on, and the lower level holds for
// the runs that start from now on.
//
// A class at the lowest level stays there; the flag is recorded all the
// same. It returns ErrNoLevels, and store.ErrUnknown for a ticket that
// ochell has never seen.
func (r *Runner) Flag(source, key, by, reason string) (store.LevelChange, error) {
	if !r.policy.Autonomy.Enabled() {
		return store.LevelChange{}, ErrNoLevels
	}
	tk, err := r.store.Ticket(source, key)
	if err != nil {
		return store.LevelChange{}, err
	}
	if tk == nil {
		return store.LevelChange{}, store.ErrUnknown
	}
	runs, err := r.store.Runs(source, key)
	if err != nil {
		return store.LevelChange{}, err
	}
	run := ""
	for _, info := range runs {
		if !info.Started.IsZero() {
			run = info.ID
		}
	}
	// A ticket whose tier the policy no longer has runs under the default
	// tier (policy.Tier), so that is its class.
	tier := r.policy.Tier(tk.Tier).Name
	r.levelMu.Lock()
	defer r.levelMu.Unlock()
	level, last := r.levelOf(tier)
	rec, err := r.record(tier, last, time.Now())
	if err != nil {
		return store.LevelChange{}, err
	}
	c, err := r.store.ChangeLevel(store.LevelChange{Class: tier, From: level, To: policy.LevelBelow(level), By: by,
		Reason: "a guardrail flagged the run: " + oneLine(reason), Record: rec, Source: source, Key: key, Run: run})
	if err != nil {
		return c, err
	}
	r.log.Warn("autonomy: a guardrail flagged a run; the class of its ticket goes down one level", "source", source, "key", key, "run", run,
		"tier", tier, "from", c.From, "to", c.To, "by", by, "reason", oneLine(reason))
	return c, nil
}

// checkLevels lowers by one level every class whose override rate is above
// the threshold of the policy: of the tickets of the class that handed
// over a pull request under its present level, within the window, more
// than autonomy.demote.sent_back_rate were sent back by a person, and
// there are at least min_sample of them.
//
// It is called when a person sends a ticket back, when a run ends, and at
// an interval, so a demotion needs no restart. After one, the class starts
// a new record at its new level.
func (r *Runner) checkLevels() {
	if !r.policy.Autonomy.Enabled() {
		return
	}
	d := r.policy.Autonomy.Demote
	r.levelMu.Lock()
	defer r.levelMu.Unlock()
	now := time.Now()
	for _, t := range r.policy.Tiers {
		level, last := r.levelOf(t.Name)
		if policy.LevelBelow(level) == level {
			continue
		}
		rec, err := r.record(t.Name, last, now)
		if err != nil {
			r.log.Error("autonomy: cannot read the outcome metrics of a class", "tier", t.Name, "err", err)
			continue
		}
		if rec.PullRequests < d.MinSample || rec.Rate() <= d.SentBackRate {
			continue
		}
		reason := fmt.Sprintf("people sent back %d of the %d tickets with a pull request since %s (%.0f%%); the policy allows %.0f%% (autonomy.demote.sent_back_rate, with at least %d tickets)",
			rec.SentBack, rec.PullRequests, rec.Since.Format("2006-01-02 15:04 UTC"), 100*rec.Rate(), 100*d.SentBackRate, d.MinSample)
		c, err := r.store.ChangeLevel(store.LevelChange{Class: t.Name, From: level, To: policy.LevelBelow(level), By: ByOchell, Reason: reason, Record: rec})
		if err != nil {
			r.log.Error("autonomy: cannot record the demotion of a class", "tier", t.Name, "err", err)
			continue
		}
		r.log.Warn("autonomy: a class was demoted: "+reason, "tier", t.Name, "from", c.From, "to", c.To)
	}
}

// runAutonomy looks at the rates of the classes at an interval, until
// Shutdown.
func (r *Runner) runAutonomy() {
	defer r.wg.Done()
	tick := time.NewTicker(autonomyInterval)
	defer tick.Stop()
	for {
		r.checkLevels()
		select {
		case <-r.quit:
			return
		case <-tick.C:
		}
	}
}
