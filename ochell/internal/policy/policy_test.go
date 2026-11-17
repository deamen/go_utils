package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const three = `
version: "2026-11"
owners: [alice@example.com]
tiers:
  - {name: low, max_turns: 30}
  - {name: normal, labels: [needs-care]}
  - {name: high, plan_gate: required, labels: [risk-high, Security]}
default_tier: normal
rules:
  - {source: jira, project: OPS, issue_type: Bug, tier: low}
  - {project: PAY, tier: high}
  - {repo: "git@example.com:org/docs.git", tier: low}
`

func TestParse(t *testing.T) {
	p, err := Parse([]byte(three))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != "2026-11" || len(p.Tiers) != 3 || p.DefaultTier != "normal" {
		t.Fatalf("policy = %+v", p)
	}
	// What a tier leaves out is the careful setting.
	if low := p.Tier("low"); low.PlanGate != PlanGateSkip || low.PRReview != PRReviewRequired || low.AutoMerge != AutoMergeNever || low.MaxTurns != 30 {
		t.Errorf("low = %+v", low)
	}
	if high := p.Tier("high"); high.PlanGate != PlanGateRequired {
		t.Errorf("high = %+v", high)
	}
	// A tier that the policy no longer has gives the default tier.
	if got := p.Tier("gone"); got.Name != "normal" {
		t.Errorf("unknown tier = %+v", got)
	}

	// Without a version, the content names it.
	a, err := Parse([]byte("tiers: [{name: only}]\ndefault_tier: only\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Parse([]byte("tiers: [{name: only, max_turns: 1}]\ndefault_tier: only\n"))
	if !strings.HasPrefix(a.Version, "sha256:") || a.Version == b.Version {
		t.Errorf("versions %q and %q", a.Version, b.Version)
	}
}

func TestMatch(t *testing.T) {
	p, err := Parse([]byte(three))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		in   Ticket
		tier string
		why  string
	}{
		{"no rule matches", Ticket{Source: "linear", Project: "ENG"}, "normal", "default_tier"},
		{"project and issue type", Ticket{Source: "jira", Project: "ops", IssueType: "bug"}, "low", "rules[0]"},
		{"the issue type does not match", Ticket{Source: "jira", Project: "OPS", IssueType: "Story"}, "normal", "default_tier"},
		{"the source does not match", Ticket{Source: "linear", Project: "OPS", IssueType: "Bug"}, "normal", "default_tier"},
		{"project alone", Ticket{Source: "linear", Project: "PAY"}, "high", "rules[1]"},
		{"repository", Ticket{Source: "jira", Project: "DOC", Repo: "git@example.com:org/docs.git"}, "low", "rules[2]"},
		{"a label raises", Ticket{Source: "jira", Project: "OPS", IssueType: "Bug", Labels: []string{"ui", "Risk-High"}}, "high", `label "risk-high"`},
		{"the highest label wins", Ticket{Source: "jira", Project: "OPS", IssueType: "Bug", Labels: []string{"needs-care", "security"}}, "high", `label "Security"`},
		{"a label raises by one", Ticket{Source: "jira", Project: "OPS", IssueType: "Bug", Labels: []string{"needs-care"}}, "normal", `label "needs-care"`},
		{"a label never lowers", Ticket{Source: "linear", Project: "PAY", Labels: []string{"needs-care"}}, "high", "rules[1]"},
	} {
		if tier, why := p.Match(c.in); tier != c.tier || why != c.why {
			t.Errorf("%s: %s (%s), want %s (%s)", c.name, tier, why, c.tier, c.why)
		}
	}
	if p.Higher("low", "high") != "high" || p.Higher("high", "low") != "high" || p.Higher("normal", "gone") != "normal" || p.Higher("gone", "low") != "low" {
		t.Error("Higher does not follow the order of the tiers")
	}
}

func TestInvalidPolicies(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"empty":                {"", "at least one tier is required"},
		"no default":           {"tiers: [{name: a}]", "default_tier is required"},
		"unknown default":      {"tiers: [{name: a}]\ndefault_tier: b", `there is no tier "b"`},
		"duplicate tier":       {"tiers: [{name: a}, {name: a}]\ndefault_tier: a", "defined twice"},
		"bad name":             {"tiers: [{name: Has Space}]\ndefault_tier: a", "a tier name is"},
		"bad plan gate":        {"tiers: [{name: a, plan_gate: maybe}]\ndefault_tier: a", "plan_gate must be skip or required"},
		"bad review":           {"tiers: [{name: a, pr_review: never}]\ndefault_tier: a", "pr_review must be required or sampled"},
		"bad merge":            {"tiers: [{name: a, auto_merge: always}]\ndefault_tier: a", "auto_merge must be never or after_ci"},
		"negative turns":       {"tiers: [{name: a, max_turns: -1}]\ndefault_tier: a", "max_turns must not be negative"},
		"misspelt setting":     {"tiers: [{name: a, max_turn: 5}]\ndefault_tier: a", "field max_turn not found"},
		"unknown top level":    {"tiers: [{name: a}]\ndefault_tier: a\nteirs: []", "field teirs not found"},
		"rule without tier":    {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{project: X}]", "rules[0].tier is required"},
		"rule unknown tier":    {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{project: X, tier: b}]", `there is no tier "b"`},
		"rule for all":         {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{tier: a}]", "matches every ticket"},
		"rule bad source":      {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{source: gitlab, tier: a}]", "source must be jira, linear, github or empty"},
		"linear issue type":    {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{source: linear, issue_type: Bug, tier: a}]", "a Linear issue has no issue type"},
		"label twice":          {"tiers: [{name: a, labels: [x]}, {name: b, labels: [X]}]\ndefault_tier: a", "also belongs to the tier a"},
		"negative tier limit":  {"tiers: [{name: a, max_concurrent: -1}]\ndefault_tier: a", "max_concurrent must not be negative"},
		"negative repo limit":  {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {max_concurrent_per_repo: -1}", "max_concurrent_per_repo must not be negative"},
		"bad blocked_by":       {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {blocked_by: maybe}", "blocked_by must be ignore or wait"},
		"empty required label": {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {required_labels: [\" \"]}", "required_labels: an empty label"},
		"required label twice": {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {required_labels: [ready, Ready]}", "listed twice"},
		"negative interval":    {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {check_interval: -1s}", "check_interval must be more than 0"},
		"priority rank":        {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {priorities: {P0: 0}}", "a rank from 1 (the most urgent) to 5"},
		"priority twice":       {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {priorities: {P0: 1, p0: 2}}", "listed twice"},
		"misspelt scheduling":  {"tiers: [{name: a}]\ndefault_tier: a\nscheduling: {required_label: [x]}", "field required_label not found"},
		"bad start level":      {"tiers: [{name: a}]\ndefault_tier: a\nautonomy: {start_level: free}", "start_level must be observe, assisted, autonomous"},
		"start at auto-merge":  {"tiers: [{name: a, auto_merge: after_ci}]\ndefault_tier: a\nautonomy: {start_level: auto-merge}", "start_level must be observe, assisted, autonomous"},
		"demote without start": {"tiers: [{name: a}]\ndefault_tier: a\nautonomy: {demote: {min_sample: 3}}", "without autonomy.start_level"},
		"bad rate":             {"tiers: [{name: a}]\ndefault_tier: a\nautonomy: {start_level: observe, demote: {sent_back_rate: 30}}", "sent_back_rate must be above 0 and at most 1"},
		"negative window":      {"tiers: [{name: a}]\ndefault_tier: a\nautonomy: {start_level: observe, demote: {window: -1h}}", "window must be more than 0"},
		"negative sample":      {"tiers: [{name: a}]\ndefault_tier: a\nautonomy: {start_level: observe, demote: {min_sample: -1}}", "min_sample must be at least 1"},
		"misspelt autonomy":    {"tiers: [{name: a}]\ndefault_tier: a\nautonomy: {start: observe}", "field start not found"},
		"not yaml":             {"tiers: [", "yaml"},
	} {
		_, err := Parse([]byte(c.in))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one with %q", name, err, c.want)
		}
	}
}

func TestBuiltin(t *testing.T) {
	p := Builtin()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if tier, why := p.Match(Ticket{Source: "jira", Project: "DEV", Labels: []string{"x"}}); tier != DefaultTierName || why != "default_tier" {
		t.Errorf("built-in policy gives %s (%s)", tier, why)
	}
}

// The policy file must be one that only root or ochell's own user can
// change.
func TestLoadChecksWhoCanWriteTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(three), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil || p.File != path {
		t.Fatalf("a private file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a file that others can only read: %v", err)
	}
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "writable by its group or by others") {
			t.Errorf("mode %04o: err = %v", mode, err)
		}
	}
	os.Chmod(path, 0o600)

	// Others can write to the directory: they could replace the file.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "could replace the file") {
		t.Errorf("a directory that others can write to: err = %v", err)
	}
	// Not with the sticky bit, as on /tmp.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a sticky directory: %v", err)
	}
	os.Chmod(dir, 0o700)

	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("a missing file was accepted")
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: err = %v", err)
	}
	if err := os.WriteFile(path, []byte("tiers: []"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("an invalid file: err = %v", err)
	}
}

// The example policy is one that ochell accepts.
func TestExamplePolicy(t *testing.T) {
	raw, err := os.ReadFile("../../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("examples/policy.yaml is not valid:\n%v", err)
	}
	if tier, _ := p.Match(Ticket{Source: "jira", Project: "PAY"}); tier != "high" || p.Tier(tier).PlanGate != PlanGateRequired {
		t.Errorf("PAY gets %q", tier)
	}
}

func TestTierAllowedAssigners(t *testing.T) {
	p, err := Parse([]byte(`
tiers:
  - {name: low}
  - {name: high, allowed_assigners: ["557058:lead", Lead@Example.com]}
default_tier: low
`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Tier("low").MayAssign("anyone") || !p.Tier("low").MayAssign() {
		t.Error("a tier without a list refuses someone")
	}
	high := p.Tier("high")
	if !high.MayAssign("557058:lead") || !high.MayAssign("", "lead@example.com") {
		t.Error("the tier refuses someone on its list")
	}
	if high.MayAssign("557058:other", "other@example.com") || high.MayAssign("") || high.MayAssign() {
		t.Error("the tier allows someone who is not on its list, or nobody")
	}
	if _, err := Parse([]byte("tiers: [{name: a, allowed_assigners: [\"\"]}]\ndefault_tier: a")); err == nil || !strings.Contains(err.Error(), "empty entry in allowed_assigners") {
		t.Errorf("an empty entry: %v", err)
	}
}

func TestNextTierAndTurnLimit(t *testing.T) {
	p, err := Parse([]byte("tiers: [{name: low, max_turns: 30}, {name: normal}, {name: high}]\ndefault_tier: low"))
	if err != nil {
		t.Fatal(err)
	}
	for from, want := range map[string]string{"low": "normal", "normal": "high", "high": "high", "gone": "gone"} {
		if got := p.Next(from); got != want {
			t.Errorf("Next(%s) = %s, want %s", from, got, want)
		}
	}
	if p.Tier("low").MaxTurns != 30 || p.Tier("normal").MaxTurns != 0 {
		t.Errorf("max_turns: %+v", p.Tiers)
	}
	if _, err := Parse([]byte("tiers: [{name: a, max_turns: -1}]\ndefault_tier: a")); err == nil || !strings.Contains(err.Error(), "max_turns must not be negative") {
		t.Errorf("a negative turn limit: %v", err)
	}
}

func TestScheduling(t *testing.T) {
	// Without the section nothing is gated, and nothing is limited.
	p, err := Parse([]byte(three))
	if err != nil {
		t.Fatal(err)
	}
	if s := p.Scheduling; s.Gated() || s.BlockedBy != BlockedByIgnore || s.CheckInterval != DefaultCheckInterval || s.MaxConcurrentPerRepo != 0 {
		t.Errorf("scheduling without the section = %+v", s)
	}
	if got := p.DescribeScheduling(); len(got) != 0 {
		t.Errorf("DescribeScheduling = %q", got)
	}
	if b := Builtin(); b.Validate() != nil || b.Scheduling.Gated() {
		t.Errorf("the built-in policy: %v, %+v", b.Validate(), b.Scheduling)
	}

	p, err = Parse([]byte(`
tiers:
  - {name: low}
  - {name: high, max_concurrent: 1}
default_tier: low
scheduling:
  max_concurrent_per_repo: 2
  required_labels: [agent-ready, Triaged]
  blocked_by: wait
  check_interval: 30s
  priorities: {P0: 1, High: 1}
`))
	if err != nil {
		t.Fatal(err)
	}
	s := p.Scheduling
	if !s.Gated() || s.MaxConcurrentPerRepo != 2 || s.CheckInterval != 30*time.Second || p.Tier("high").MaxConcurrent != 1 {
		t.Errorf("scheduling = %+v", s)
	}
	if got, want := strings.Join(p.DescribeScheduling(), " "), "max_concurrent_per_repo=2 required_labels=agent-ready,Triaged blocked_by=wait check_interval=30s"; got != want {
		t.Errorf("DescribeScheduling = %q, want %q", got, want)
	}
	if got := strings.Join(p.Describe(), "\n"); !strings.Contains(got, "high: plan_gate=skip pr_review=required auto_merge=never max_concurrent=1") {
		t.Errorf("Describe = %q", got)
	}
	// A gate alone is enough.
	for _, one := range []Scheduling{{RequiredLabels: []string{"x"}}, {BlockedBy: BlockedByWait}} {
		if !one.Gated() {
			t.Errorf("%+v is not gated", one)
		}
	}

	// The rank of a priority, by its name in Jira: the names that Jira
	// comes with, and the ones of the policy, which win.
	for name, want := range map[string]int{
		"Highest": 1, "high": 1, " Medium ": 3, "Low": 4, "Lowest": 5,
		"Blocker": 1, "Critical": 2, "Major": 3, "Minor": 4, "Trivial": 5,
		"p0": 1, "Sev-9": 0, "": 0,
	} {
		if got := s.Rank(name); got != want {
			t.Errorf("Rank(%q) = %d, want %d", name, got, want)
		}
	}

	// Every required label must be there; case and spaces do not matter.
	for _, c := range []struct {
		have []string
		want string
	}{
		{nil, "agent-ready,Triaged"},
		{[]string{"Agent-Ready"}, "Triaged"},
		{[]string{"triaged ", "agent-ready", "other"}, ""},
	} {
		if got := strings.Join(s.Missing(c.have), ","); got != c.want {
			t.Errorf("Missing(%q) = %q, want %q", c.have, got, c.want)
		}
	}
}

// The levels of autonomy: what the policy file sets, which level a class
// can have, and what a level holds back of a tier.
func TestAutonomy(t *testing.T) {
	// A policy without the section has no levels, and a tier holds as it
	// is written.
	p, err := Parse([]byte("tiers: [{name: a, pr_review: sampled, auto_merge: after_ci}]\ndefault_tier: a"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Autonomy.Enabled() || p.Level("a", LevelAutonomous) != "" || p.DescribeAutonomy() != "" || Builtin().Autonomy.Enabled() {
		t.Errorf("a policy without autonomy has levels: %+v", p.Autonomy)
	}
	if got := Narrow(p.Tier("a"), p.Level("a", "")); got.PRReview != PRReviewSampled || got.AutoMerge != AutoMergeAfterCI || got.PlanGate != PlanGateSkip {
		t.Errorf("without levels the tier is narrowed: %+v", got)
	}

	p, err = Parse([]byte(`
tiers:
  - {name: low, pr_review: sampled, auto_merge: after_ci}
  - {name: high, plan_gate: required, pr_review: sampled, auto_merge: after_ci}
default_tier: low
autonomy:
  start_level: assisted
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Autonomy.Demote; d.SentBackRate != DefaultSentBackRate || d.Window != DefaultDemoteWindow || d.MinSample != DefaultMinSample {
		t.Errorf("defaults of demote = %+v", d)
	}
	if got, want := p.DescribeAutonomy(), "start_level=assisted demote: sent_back_rate=0.3 window=336h0m0s min_sample=5"; got != want {
		t.Errorf("DescribeAutonomy = %q, want %q", got, want)
	}
	// Only the lowest tier can reach auto-merge, and only with after_ci.
	if p.MaxLevel("low") != LevelAutoMerge || p.MaxLevel("high") != LevelAutonomous {
		t.Errorf("MaxLevel: low %s, high %s", p.MaxLevel("low"), p.MaxLevel("high"))
	}
	never, _ := Parse([]byte("tiers: [{name: low}]\ndefault_tier: low\nautonomy: {start_level: observe, demote: {sent_back_rate: 0.5, window: 24h, min_sample: 2}}"))
	if never.MaxLevel("low") != LevelAutonomous || never.Autonomy.Demote != (Demote{SentBackRate: 0.5, Window: 24 * time.Hour, MinSample: 2}) {
		t.Errorf("a lowest tier with auto_merge: never: max %s, %+v", never.MaxLevel("low"), never.Autonomy.Demote)
	}
	for _, c := range []struct{ tier, stored, want string }{
		{"low", "", LevelAssisted},                 // nobody changed it: the start level
		{"low", LevelObserve, LevelObserve},        //
		{"low", LevelAutoMerge, LevelAutoMerge},    //
		{"high", LevelAutoMerge, LevelAutonomous},  // the file changed since: the highest it can have
		{"high", "something", LevelAssisted},       // not a level
		{"gone", LevelAutonomous, LevelAutonomous}, // a tier that the policy no longer has
	} {
		if got := p.Level(c.tier, c.stored); got != c.want {
			t.Errorf("Level(%s, %q) = %q, want %q", c.tier, c.stored, got, c.want)
		}
	}
	if LevelAbove(LevelObserve) != LevelAssisted || LevelAbove(LevelAutoMerge) != LevelAutoMerge || LevelBelow(LevelAssisted) != LevelObserve || LevelBelow(LevelObserve) != LevelObserve {
		t.Error("LevelAbove and LevelBelow do not move one step")
	}

	// What a level leaves of a tier: never more than the tier says.
	for _, c := range []struct{ tier, level, plan, review, merge string }{
		{"low", LevelObserve, PlanGateRequired, PRReviewRequired, AutoMergeNever},
		{"low", LevelAssisted, PlanGateSkip, PRReviewRequired, AutoMergeNever},
		{"low", LevelAutonomous, PlanGateSkip, PRReviewSampled, AutoMergeNever},
		{"low", LevelAutoMerge, PlanGateSkip, PRReviewSampled, AutoMergeAfterCI},
		{"high", LevelAssisted, PlanGateRequired, PRReviewRequired, AutoMergeNever},
		{"high", LevelAutonomous, PlanGateRequired, PRReviewSampled, AutoMergeNever},
	} {
		got := Narrow(p.Tier(c.tier), c.level)
		if got.PlanGate != c.plan || got.PRReview != c.review || got.AutoMerge != c.merge {
			t.Errorf("%s at %s: plan_gate=%s pr_review=%s auto_merge=%s", c.tier, c.level, got.PlanGate, got.PRReview, got.AutoMerge)
		}
	}
	// A tier that is strict already stays strict at every level.
	strict := Tier{Name: "s", PlanGate: PlanGateRequired, PRReview: PRReviewRequired, AutoMerge: AutoMergeNever}
	for _, l := range Levels {
		if got := Narrow(strict, l); got.PlanGate != strict.PlanGate || got.PRReview != strict.PRReview || got.AutoMerge != strict.AutoMerge {
			t.Errorf("a strict tier at %s was widened: %+v", l, got)
		}
	}
}
