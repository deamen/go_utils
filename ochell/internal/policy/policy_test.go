package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const three = `
version: "2026-11"
owners: [alice@example.com]
tiers:
  - {name: low, budget_usd: 5}
  - {name: normal, budget_usd: 20, labels: [needs-care]}
  - {name: high, plan_gate: required, budget_usd: 50, labels: [risk-high, Security]}
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
	if low := p.Tier("low"); low.PlanGate != PlanGateSkip || low.PRReview != PRReviewRequired || low.AutoMerge != AutoMergeNever || low.BudgetUSD != 5 {
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
	b, _ := Parse([]byte("tiers: [{name: only, budget_usd: 1}]\ndefault_tier: only\n"))
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
		"empty":             {"", "at least one tier is required"},
		"no default":        {"tiers: [{name: a}]", "default_tier is required"},
		"unknown default":   {"tiers: [{name: a}]\ndefault_tier: b", `there is no tier "b"`},
		"duplicate tier":    {"tiers: [{name: a}, {name: a}]\ndefault_tier: a", "defined twice"},
		"bad name":          {"tiers: [{name: Has Space}]\ndefault_tier: a", "a tier name is"},
		"bad plan gate":     {"tiers: [{name: a, plan_gate: maybe}]\ndefault_tier: a", "plan_gate must be skip or required"},
		"bad review":        {"tiers: [{name: a, pr_review: never}]\ndefault_tier: a", "pr_review must be required or sampled"},
		"bad merge":         {"tiers: [{name: a, auto_merge: always}]\ndefault_tier: a", "auto_merge must be never or after_ci"},
		"negative budget":   {"tiers: [{name: a, budget_usd: -1}]\ndefault_tier: a", "budget_usd must not be negative"},
		"misspelt setting":  {"tiers: [{name: a, budget: 5}]\ndefault_tier: a", "field budget not found"},
		"unknown top level": {"tiers: [{name: a}]\ndefault_tier: a\nteirs: []", "field teirs not found"},
		"rule without tier": {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{project: X}]", "rules[0].tier is required"},
		"rule unknown tier": {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{project: X, tier: b}]", `there is no tier "b"`},
		"rule for all":      {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{tier: a}]", "matches every ticket"},
		"rule bad source":   {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{source: github, tier: a}]", "source must be jira, linear or empty"},
		"linear issue type": {"tiers: [{name: a}]\ndefault_tier: a\nrules: [{source: linear, issue_type: Bug, tier: a}]", "a Linear issue has no issue type"},
		"label twice":       {"tiers: [{name: a, labels: [x]}, {name: b, labels: [X]}]\ndefault_tier: a", "also belongs to the tier a"},
		"not yaml":          {"tiers: [", "yaml"},
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
