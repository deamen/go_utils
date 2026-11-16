package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"ochell/internal/config"
	"ochell/internal/policy"
	"ochell/internal/result"
	"ochell/internal/store"
	"ochell/internal/task"
)

const autonomyPolicy = `
tiers:
  - {name: low, pr_review: sampled, auto_merge: after_ci}
  - {name: high, plan_gate: required}
default_tier: low
autonomy:
  start_level: assisted
  demote: {sent_back_rate: 0.5, window: 1h, min_sample: 3}
`

// levelRunner is a runner with a policy, whose store a test fills with
// runs itself: no agent is started.
type levelRunner struct {
	*Runner
	st  *store.Store
	seq int
}

func newLevelRunner(t *testing.T, pol string) *levelRunner {
	t.Helper()
	p, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	st := testStore(t)
	r, err := New(agentCfg(t, "echo"), logger(), st)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UsePolicy(p); err != nil {
		t.Fatal(err)
	}
	return &levelRunner{Runner: r, st: st}
}

// ran records one run of a ticket as the store would have it: queued (as
// a follow-up of a person, with sentBack), started and ended with the work
// handed over. It returns the id of the run.
func (l *levelRunner) ran(t *testing.T, key, tier string, sentBack bool) string {
	t.Helper()
	// The store keeps times in milliseconds, and "after the pull request"
	// is a comparison of two of them.
	time.Sleep(3 * time.Millisecond)
	l.seq++
	tk := &task.Task{ID: fmt.Sprintf("r%d", l.seq), Source: "linear", Key: key, Tier: tier, Received: time.Now()}
	var err error
	if sentBack {
		// As the server does for a message of a person.
		_, err = l.FollowUp(tk, true)
	} else {
		err = l.st.Enqueue(tk, store.Limits{})
	}
	if err != nil {
		t.Fatal(err)
	}
	if got, err := l.st.Claim(); err != nil || got == nil || got.ID != tk.ID {
		t.Fatalf("Claim = %+v, %v; want %s", got, err, tk.ID)
	}
	res := task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}
	if !sentBack {
		res.PRURL = "https://example.test/pr/" + key
	}
	if err := l.st.Finish(tk.ID, res); err != nil {
		t.Fatal(err)
	}
	return tk.ID
}

func (l *levelRunner) level(tier string) string {
	level, _ := l.levelOf(tier)
	return level
}

// The done-when of graduated autonomy, on the runner: a class with a good
// record is promoted by an operator, which is recorded with who decided
// and the numbers; and when people send back more of its pull requests
// than the policy allows, ochell demotes it by itself.
func TestPromotionAndAutomaticDemotion(t *testing.T) {
	l := newLevelRunner(t, autonomyPolicy)
	if l.level("low") != policy.LevelAssisted || l.level("high") != policy.LevelAssisted {
		t.Fatalf("start levels: low %s, high %s", l.level("low"), l.level("high"))
	}
	// A good record: three pull requests, none sent back.
	for _, key := range []string{"ENG-1", "ENG-2", "ENG-3"} {
		l.ran(t, key, "low", false)
	}
	l.checkLevels()
	if l.level("low") != policy.LevelAssisted {
		t.Fatalf("a class with a good record was demoted to %s", l.level("low"))
	}
	up, err := l.Promote("low", "the operator ada", "three weeks\nwithout a problem")
	if err != nil || up.From != policy.LevelAssisted || up.To != policy.LevelAutonomous || up.By != "the operator ada" || up.Reason != "three weeks without a problem" ||
		up.Record.PullRequests != 3 || up.Record.SentBack != 0 || up.Record.Tickets != 3 || up.At.IsZero() {
		t.Fatalf("Promote = %+v, %v", up, err)
	}
	if l.level("low") != policy.LevelAutonomous || l.level("high") != policy.LevelAssisted {
		t.Errorf("after the promotion: low %s, high %s", l.level("low"), l.level("high"))
	}

	// Under the new level the class earns a new record. One ticket of three
	// sent back is within what the policy allows (50%).
	for _, key := range []string{"ENG-4", "ENG-5", "ENG-6"} {
		l.ran(t, key, "low", false)
	}
	// Another class does not count.
	l.ran(t, "PAY-1", "high", false)
	l.ran(t, "PAY-1", "high", true)
	l.ran(t, "ENG-4", "low", true)
	if l.level("low") != policy.LevelAutonomous {
		t.Fatalf("one ticket of three sent back demoted the class to %s", l.level("low"))
	}
	// A second follow-up on the same ticket is still one ticket.
	l.ran(t, "ENG-4", "low", true)
	if l.level("low") != policy.LevelAutonomous {
		t.Fatalf("two follow-ups on one ticket demoted the class to %s", l.level("low"))
	}
	// The second ticket sent back takes the rate above the threshold: the
	// follow-up itself makes ochell look.
	l.ran(t, "ENG-5", "low", true)
	if l.level("low") != policy.LevelAssisted {
		t.Fatalf("two tickets of three sent back: the class is at %s, want assisted", l.level("low"))
	}
	_, last := l.levelOf("low")
	if last == nil || last.By != ByOchell || last.From != policy.LevelAutonomous || last.To != policy.LevelAssisted ||
		last.Record.PullRequests != 3 || last.Record.SentBack != 2 || !strings.Contains(last.Reason, "people sent back 2 of the 3 tickets") || !strings.Contains(last.Reason, "the policy allows 50%") {
		t.Errorf("the demotion as recorded = %+v", last)
	}
	// One bad stretch takes one level: the record starts anew.
	l.checkLevels()
	l.ran(t, "ENG-6", "low", true)
	if l.level("low") != policy.LevelAssisted {
		t.Errorf("the same tickets demoted the class twice: %s", l.level("low"))
	}
	// The class of the other tier: one ticket of one sent back is below the
	// minimum sample.
	if l.level("high") != policy.LevelAssisted {
		t.Errorf("one ticket demoted the class of high to %s", l.level("high"))
	}

	// What an operator sees.
	classes, changes, err := l.Autonomy()
	if err != nil || len(classes) != 2 || len(changes) != 2 || changes[0].By != ByOchell || changes[1].By != "the operator ada" {
		t.Fatalf("Autonomy = %+v, %+v, %v", classes, changes, err)
	}
	if c := classes[0]; c.Tier != "low" || c.Level != policy.LevelAssisted || c.By != ByOchell || c.Since == nil || c.Record == nil || c.Record.PullRequests != 0 {
		t.Errorf("the class of low = %+v, record %+v", c, c.Record)
	}
	if c := classes[1]; c.Tier != "high" || c.Level != policy.LevelAssisted || c.Since != nil || c.By != "" || c.Record.PullRequests != 1 || c.Record.SentBack != 1 {
		t.Errorf("the class of high = %+v, record %+v", c, c.Record)
	}
	if st, err := l.Status(); err != nil || len(st.Autonomy) != 2 || st.Autonomy[0].Level != policy.LevelAssisted || st.Autonomy[0].Record != nil {
		t.Errorf("Status().Autonomy = %+v, %v", st.Autonomy, err)
	}
}

// How far a class can go, up and down.
func TestLevelBounds(t *testing.T) {
	l := newLevelRunner(t, autonomyPolicy)
	// The lowest tier, with auto_merge: after_ci, can reach auto-merge.
	for _, want := range []string{policy.LevelAutonomous, policy.LevelAutoMerge} {
		if c, err := l.Promote("low", "an operator", ""); err != nil || c.To != want {
			t.Fatalf("Promote(low) = %+v, %v; want %s", c, err, want)
		}
	}
	if _, err := l.Promote("low", "an operator", ""); !errors.Is(err, ErrTopLevel) {
		t.Errorf("a promotion above auto-merge: %v", err)
	}
	// No other tier can.
	if c, err := l.Promote("high", "an operator", ""); err != nil || c.To != policy.LevelAutonomous {
		t.Fatalf("Promote(high) = %+v, %v", c, err)
	}
	if _, err := l.Promote("high", "an operator", ""); !errors.Is(err, ErrTopLevel) || !strings.Contains(err.Error(), "for the lowest tier of the policy (low) alone") {
		t.Errorf("a promotion of high to auto-merge: %v", err)
	}
	if _, err := l.Promote("nope", "an operator", ""); !errors.Is(err, ErrNoTier) {
		t.Errorf("a promotion of a tier that is not there: %v", err)
	}
	// Down by hand, one step at a time, to the lowest level.
	for _, want := range []string{policy.LevelAssisted, policy.LevelObserve} {
		if c, err := l.Demote("high", "an operator", "by hand"); err != nil || c.To != want {
			t.Fatalf("Demote(high) = %+v, %v; want %s", c, err, want)
		}
	}
	if _, err := l.Demote("high", "an operator", ""); !errors.Is(err, ErrLowestLevel) {
		t.Errorf("a demotion below observe: %v", err)
	}

	// A policy without levels has nothing to change, and holds nothing back.
	none := newLevelRunner(t, "tiers: [{name: low, pr_review: sampled}]\ndefault_tier: low")
	if _, err := none.Promote("low", "an operator", ""); !errors.Is(err, ErrNoLevels) {
		t.Errorf("Promote without levels: %v", err)
	}
	if _, err := none.Flag("linear", "ENG-1", "an operator", "x"); !errors.Is(err, ErrNoLevels) {
		t.Errorf("Flag without levels: %v", err)
	}
	if _, _, err := none.Autonomy(); !errors.Is(err, ErrNoLevels) {
		t.Errorf("Autonomy without levels: %v", err)
	}
	if st, err := none.Status(); err != nil || st.Autonomy != nil || none.level("low") != "" {
		t.Errorf("without levels: status %+v, %v; level %q", st.Autonomy, err, none.level("low"))
	}
	none.checkLevels()
}

// A guardrail outside ochell flags a run: the flag is recorded with the
// run, and the class of the ticket goes down one level.
func TestGuardrailFlag(t *testing.T) {
	l := newLevelRunner(t, autonomyPolicy)
	run := l.ran(t, "ENG-1", "low", false)
	c, err := l.Flag("linear", "ENG-1", "the operator ci-watch", "the pull request\nfailed CI three times")
	if err != nil || c.Class != "low" || c.From != policy.LevelAssisted || c.To != policy.LevelObserve || c.By != "the operator ci-watch" ||
		c.Source != "linear" || c.Key != "ENG-1" || c.Run != run || c.Reason != "a guardrail flagged the run: the pull request failed CI three times" || c.Record.PullRequests != 1 {
		t.Fatalf("Flag = %+v, %v", c, err)
	}
	if l.level("low") != policy.LevelObserve || l.level("high") != policy.LevelAssisted {
		t.Errorf("after the flag: low %s, high %s", l.level("low"), l.level("high"))
	}
	// The ticket is not touched.
	if tk, _ := l.st.Ticket("linear", "ENG-1"); tk == nil || tk.State != "in_review" || tk.Tier != "low" {
		t.Errorf("the flagged ticket = %+v", tk)
	}
	// At the lowest level the flag is recorded, and nothing changes.
	if c, err := l.Flag("linear", "ENG-1", "an operator", "again"); err != nil || c.From != policy.LevelObserve || c.To != policy.LevelObserve || c.Run != run {
		t.Errorf("a flag at the lowest level = %+v, %v", c, err)
	}
	if _, err := l.Flag("linear", "NOPE-1", "an operator", "x"); !errors.Is(err, store.ErrUnknown) {
		t.Errorf("a flag on a ticket that ochell does not know: %v", err)
	}
	if list, _ := l.st.LevelChanges(0); len(list) != 2 {
		t.Errorf("recorded changes = %+v", list)
	}
}

// A level and a repository's WORKFLOW.md both hold a tier back, and
// neither gives back what the other took.
func TestLevelAndWorkflowOnlyNarrow(t *testing.T) {
	l := newLevelRunner(t, autonomyPolicy)
	src := &fakeSource{}
	l.UseWorkflow(config.Workflow{Enabled: true}, src)
	flowAt := func(level string) *flow {
		tk := newTask()
		tk.Repo, tk.Tier, tk.Autonomy = testRepo, "low", level
		return l.flow(context.Background(), tk, logger())
	}
	// The file asks for what the tier allows but the level does not carry
	// yet: it is ignored, as widening.
	src.set("v1", "---\npr_review: sampled\nauto_merge: after_ci\n---\n")
	f := flowAt(policy.LevelAssisted)
	if f.Tier.PRReview != policy.PRReviewRequired || f.Tier.AutoMerge != policy.AutoMergeNever || f.Tier.PlanGate != policy.PlanGateSkip || len(f.Ignored) != 2 {
		t.Errorf("at assisted: %+v, ignored %q", f.Tier, f.Ignored)
	}
	if f := flowAt(policy.LevelObserve); f.Tier.PlanGate != policy.PlanGateRequired || f.Tier.PRReview != policy.PRReviewRequired {
		t.Errorf("at observe: %+v", f.Tier)
	}
	// At the level that carries them, the tier's settings hold, and the
	// file agrees with them.
	if f := flowAt(policy.LevelAutoMerge); f.Tier.PRReview != policy.PRReviewSampled || f.Tier.AutoMerge != policy.AutoMergeAfterCI || len(f.Ignored) != 0 {
		t.Errorf("at auto-merge: %+v, ignored %q", f.Tier, f.Ignored)
	}
	// And a file that is stricter than the level stays stricter.
	src.set("v2", "---\nplan_gate: required\nauto_merge: never\n---\n")
	if f := flowAt(policy.LevelAutoMerge); f.Tier.PlanGate != policy.PlanGateRequired || f.Tier.AutoMerge != policy.AutoMergeNever || f.Tier.PRReview != policy.PRReviewSampled {
		t.Errorf("a strict file at auto-merge: %+v", f.Tier)
	}
}
