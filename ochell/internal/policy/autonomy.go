package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The levels of autonomy of a class of work, from the least to the most.
// A class of work is the tickets of one tier.
const (
	// LevelObserve: every ticket of the class gets a run that only plans,
	// and a person approves the plan before anything is changed.
	LevelObserve = "observe"
	// LevelAssisted: the plan gate is the tier's own; a person reviews
	// every pull request.
	LevelAssisted = "assisted"
	// LevelAutonomous: pr_review: sampled of the tier counts.
	LevelAutonomous = "autonomous"
	// LevelAutoMerge: auto_merge: after_ci of the tier counts. Only the
	// lowest tier can be at this level.
	LevelAutoMerge = "auto-merge"
)

// Levels are the levels of autonomy in their order.
var Levels = []string{LevelObserve, LevelAssisted, LevelAutonomous, LevelAutoMerge}

// Defaults of autonomy.demote.
const (
	DefaultSentBackRate = 0.3
	DefaultDemoteWindow = 14 * 24 * time.Hour
	DefaultMinSample    = 5
)

// Autonomy is the graduated autonomy of the classes of work. The settings
// here are the reviewed part: where a class starts, and when ochell takes
// a level away by itself. The level a class has now is not in the file: an
// operator raises it with a command, and ochell keeps it in its store.
//
// A level never gives a class more than its tier says. It only holds back
// what the tier allows (Narrow).
type Autonomy struct {
	// StartLevel is the level of a class whose level nobody has changed
	// yet: observe, assisted or autonomous. Empty: there are no levels,
	// and every tier holds as it is written.
	StartLevel string `yaml:"start_level"`
	// Demote says when ochell lowers the level of a class by itself.
	Demote Demote `yaml:"demote"`
}

// Demote says when a class loses one level without anyone deciding it.
type Demote struct {
	// SentBackRate is the share of the tickets with a pull request that
	// people may send back with a follow-up. When the share of a class is
	// above it, the class goes down one level. 1: never.
	SentBackRate float64 `yaml:"sent_back_rate"`
	// Window is how far back the tickets count.
	Window time.Duration `yaml:"window"`
	// MinSample is how many tickets with a pull request a class must have
	// in the window before its rate counts, so that one ticket does not
	// take a level away.
	MinSample int `yaml:"min_sample"`
}

// Enabled reports whether the classes of work have levels.
func (a Autonomy) Enabled() bool { return a.StartLevel != "" }

// LevelRank returns the position of a level in Levels, -1 for a word that
// is not a level.
func LevelRank(level string) int { return slices.Index(Levels, level) }

// LevelBelow returns the level one below the given one, and LevelAbove the
// one above. The lowest and the highest level, and a word that is not a
// level, are returned as they are.
func LevelBelow(level string) string {
	if i := LevelRank(level); i > 0 {
		return Levels[i-1]
	}
	return level
}

func LevelAbove(level string) string {
	if i := LevelRank(level); i >= 0 && i+1 < len(Levels) {
		return Levels[i+1]
	}
	return level
}

// setDefaults fills in what a file with levels leaves out.
func (a *Autonomy) setDefaults() {
	if !a.Enabled() {
		return
	}
	if a.Demote.SentBackRate == 0 {
		a.Demote.SentBackRate = DefaultSentBackRate
	}
	if a.Demote.Window == 0 {
		a.Demote.Window = DefaultDemoteWindow
	}
	if a.Demote.MinSample == 0 {
		a.Demote.MinSample = DefaultMinSample
	}
}

// validate checks the autonomy settings.
func (a Autonomy) validate() []error {
	if !a.Enabled() {
		if a.Demote != (Demote{}) {
			return []error{errors.New("autonomy.demote is set without autonomy.start_level: there are no levels to take away")}
		}
		return nil
	}
	var errs []error
	// A class reaches auto-merge by a promotion only, never by the file.
	if r := LevelRank(a.StartLevel); r < 0 || a.StartLevel == LevelAutoMerge {
		errs = append(errs, fmt.Errorf("autonomy.start_level must be %s", strings.Join(Levels[:len(Levels)-1], ", ")))
	}
	if d := a.Demote; d.SentBackRate <= 0 || d.SentBackRate > 1 {
		errs = append(errs, errors.New("autonomy.demote.sent_back_rate must be above 0 and at most 1 (1: never)"))
	}
	if a.Demote.Window <= 0 {
		errs = append(errs, errors.New("autonomy.demote.window must be more than 0"))
	}
	if a.Demote.MinSample < 1 {
		errs = append(errs, errors.New("autonomy.demote.min_sample must be at least 1"))
	}
	return errs
}

// MaxLevel returns the highest level that the class of a tier can have.
// That is autonomous, and auto-merge for the lowest tier when it sets
// auto_merge: after_ci.
func (p *Policy) MaxLevel(tier string) string {
	if i := p.rank(tier); i == 0 && p.Tiers[0].AutoMerge == AutoMergeAfterCI {
		return LevelAutoMerge
	}
	return LevelAutonomous
}

// Level returns the level in force for the class of a tier, given the level
// that the store has for it; empty: nobody has changed it. It is empty
// when the policy has no levels.
//
// A level that the class can no longer have, because the file changed since
// the promotion, counts as the highest it can have.
func (p *Policy) Level(tier, stored string) string {
	if !p.Autonomy.Enabled() {
		return ""
	}
	level := stored
	if LevelRank(level) < 0 {
		level = p.Autonomy.StartLevel
	}
	if max := p.MaxLevel(tier); LevelRank(level) > LevelRank(max) {
		level = max
	}
	return level
}

// Narrow returns a tier as it holds at a level of autonomy. A level only
// holds back what the tier allows, so the result is never wider than t:
//
//   - observe: the plan gate is required, whatever the tier says;
//   - below autonomous: every pull request is reviewed;
//   - below auto-merge: nothing is merged without a person.
//
// An empty level (a policy without levels) changes nothing.
func Narrow(t Tier, level string) Tier {
	r := LevelRank(level)
	if r < 0 {
		return t
	}
	if r <= LevelRank(LevelObserve) {
		t.PlanGate = PlanGateRequired
	}
	if r < LevelRank(LevelAutonomous) {
		t.PRReview = PRReviewRequired
	}
	if r < LevelRank(LevelAutoMerge) {
		t.AutoMerge = AutoMergeNever
	}
	return t
}

// DescribeAutonomy is the autonomy settings in one line, for the log and
// for "ochell policy-check"; empty when the policy has no levels.
func (p *Policy) DescribeAutonomy() string {
	a := p.Autonomy
	if !a.Enabled() {
		return ""
	}
	return fmt.Sprintf("start_level=%s demote: sent_back_rate=%g window=%s min_sample=%d", a.StartLevel, a.Demote.SentBackRate, a.Demote.Window, a.Demote.MinSample)
}
