// Package policy is the host-enforced policy of ochell: the risk tiers, and
// the rules that say which tier a ticket runs under.
//
// The policy is a file of its own in ochell's configuration. Nothing in a
// ticket, a repository or the agent's working directory can change it: the
// file must not be writable by the agent's OS user, and a change to it goes
// through the review of whoever owns ochell's configuration. That review is
// how people decide, ahead of time, how much autonomy a class of work gets.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Values of a tier's settings.
const (
	PlanGateSkip     = "skip"
	PlanGateRequired = "required"

	PRReviewRequired = "required"
	PRReviewSampled  = "sampled"

	AutoMergeNever   = "never"
	AutoMergeAfterCI = "after_ci"
)

// DefaultTierName is the one tier of the built-in policy.
const DefaultTierName = "normal"

// Tier says how much autonomy a class of work gets.
type Tier struct {
	// Name identifies the tier in rules, in the store and in the log.
	Name string `yaml:"name"`
	// PlanGate is "required" when the agent must have its plan approved by
	// a person before it implements it, and "skip" otherwise.
	PlanGate string `yaml:"plan_gate"`
	// PRReview is "required" when a person reviews every pull request, and
	// "sampled" when only some are.
	PRReview string `yaml:"pr_review"`
	// AutoMerge is "never", or "after_ci" for work that may be merged
	// without a person once CI is green.
	AutoMerge string `yaml:"auto_merge"`
	// BudgetUSD is what a ticket of this tier may cost; 0: no limit.
	BudgetUSD float64 `yaml:"budget_usd"`
	// MaxTurns is how many turns one run of this tier may take; 0: no
	// limit.
	MaxTurns int `yaml:"max_turns"`
	// Labels raise a ticket to this tier: a ticket that carries one of
	// them runs under this tier, unless its rule already gives it a
	// higher one. A label never lowers a tier.
	Labels []string `yaml:"labels"`
	// AllowedAssigners, when not empty, are the people who may assign work
	// of this tier: Jira accountIds, Linear user ids or email addresses.
	// It narrows the allowlist of the source (allowed_assigners in the
	// configuration), which is checked first. Empty: everyone whom the
	// source allows.
	AllowedAssigners []string `yaml:"allowed_assigners"`
	// Approvers, when not empty, are the people who may approve a plan of
	// this tier: Jira accountIds, Linear user ids or email addresses.
	// Empty: everyone who may send the agent a follow-up on the ticket.
	Approvers []string `yaml:"approvers"`
}

// MayApprove reports whether one of ids names someone who may approve a
// plan of this tier, as far as the tier itself says: without a list, the
// rules for follow-ups decide alone.
func (t Tier) MayApprove(ids ...string) bool {
	if len(t.Approvers) == 0 {
		return true
	}
	for _, id := range ids {
		if id != "" && slices.ContainsFunc(t.Approvers, func(a string) bool { return strings.EqualFold(strings.TrimSpace(a), id) }) {
			return true
		}
	}
	return false
}

// MayAssign reports whether one of ids, the ways a source names the person
// who assigned a ticket, is allowed to assign work of this tier.
func (t Tier) MayAssign(ids ...string) bool {
	if len(t.AllowedAssigners) == 0 {
		return true
	}
	for _, id := range ids {
		if id != "" && slices.ContainsFunc(t.AllowedAssigners, func(a string) bool { return strings.EqualFold(strings.TrimSpace(a), id) }) {
			return true
		}
	}
	return false
}

// Rule gives a tier to the tickets it matches. Every field that is set
// must match; at least one must be set.
type Rule struct {
	// Source is "jira" or "linear".
	Source string `yaml:"source"`
	// Project is the Jira project key or the Linear team key: the part of
	// the ticket key before the number.
	Project string `yaml:"project"`
	// Repo is the repository mapped to the ticket (the repos setting).
	Repo string `yaml:"repo"`
	// IssueType is the Jira issue type, such as "Bug". Linear has none.
	IssueType string `yaml:"issue_type"`
	// Tier is the name of the tier the matching tickets get.
	Tier string `yaml:"tier"`
}

// Policy is the content of a policy file.
type Policy struct {
	// Version names this state of the policy in the record of each run.
	// Empty: a hash of the file is used.
	Version string `yaml:"version"`
	// Owners are the people who answer for the policy. ochell only keeps
	// the list; it is there for whoever reads the file.
	Owners []string `yaml:"owners"`
	// Tiers are listed from the lowest to the highest: from the most
	// autonomy to the least. An escalation moves a ticket up this list.
	Tiers []Tier `yaml:"tiers"`
	// DefaultTier is the tier of a ticket that no rule matches.
	DefaultTier string `yaml:"default_tier"`
	// Rules are tried in order; the first that matches a ticket wins.
	Rules []Rule `yaml:"rules"`

	// File is where the policy was read from; empty for the built-in one.
	File string `yaml:"-"`
}

// Builtin is the policy of an ochell that has no policy file: one tier,
// under which every ticket runs as it did before there were tiers.
func Builtin() *Policy {
	return &Policy{
		Version:     "builtin",
		Tiers:       []Tier{{Name: DefaultTierName, PlanGate: PlanGateSkip, PRReview: PRReviewRequired, AutoMerge: AutoMergeNever}},
		DefaultTier: DefaultTierName,
	}
}

// Load reads and checks the policy file at path. It refuses a file that
// someone other than its owner could change.
func Load(path string) (*Policy, error) {
	if err := CheckFile(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	p.File = path
	return p, nil
}

// Parse reads and checks the content of a policy file. A setting that
// ochell does not know is an error: in a policy, a misspelt limit must not
// silently mean no limit.
func Parse(raw []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for i := range p.Tiers {
		t := &p.Tiers[i]
		if t.PlanGate == "" {
			t.PlanGate = PlanGateSkip
		}
		if t.PRReview == "" {
			t.PRReview = PRReviewRequired
		}
		if t.AutoMerge == "" {
			t.AutoMerge = AutoMergeNever
		}
	}
	if p.Version == "" {
		sum := sha256.Sum256(raw)
		p.Version = "sha256:" + hex.EncodeToString(sum[:6])
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// tierName is what a tier may be called. The name reaches the agent's
// environment and the log.
var tierName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Validate checks that the policy says something definite for every ticket.
func (p *Policy) Validate() error {
	var errs []error
	if len(p.Tiers) == 0 {
		errs = append(errs, errors.New("tiers: at least one tier is required"))
	}
	if strings.ContainsAny(p.Version, " \t\n\r") || len(p.Version) > 64 {
		errs = append(errs, errors.New("version must be one word of at most 64 characters"))
	}
	seen := map[string]bool{}
	labels := map[string]string{}
	for i, t := range p.Tiers {
		at := fmt.Sprintf("tiers[%d]", i)
		switch {
		case !tierName.MatchString(t.Name):
			errs = append(errs, fmt.Errorf("%s.name %q: a tier name is lower-case letters, digits, - and _", at, t.Name))
		case seen[t.Name]:
			errs = append(errs, fmt.Errorf("%s: the tier %s is defined twice", at, t.Name))
		}
		seen[t.Name] = true
		if t.Name != "" {
			at = "tier " + t.Name
		}
		if t.PlanGate != PlanGateSkip && t.PlanGate != PlanGateRequired {
			errs = append(errs, fmt.Errorf("%s: plan_gate must be skip or required", at))
		}
		if t.PRReview != PRReviewRequired && t.PRReview != PRReviewSampled {
			errs = append(errs, fmt.Errorf("%s: pr_review must be required or sampled", at))
		}
		if t.AutoMerge != AutoMergeNever && t.AutoMerge != AutoMergeAfterCI {
			errs = append(errs, fmt.Errorf("%s: auto_merge must be never or after_ci", at))
		}
		if t.BudgetUSD < 0 {
			errs = append(errs, fmt.Errorf("%s: budget_usd must not be negative; 0 means no limit", at))
		}
		if t.MaxTurns < 0 {
			errs = append(errs, fmt.Errorf("%s: max_turns must not be negative; 0 means no limit", at))
		}
		for _, l := range t.Labels {
			key := strings.ToLower(strings.TrimSpace(l))
			if key == "" {
				errs = append(errs, fmt.Errorf("%s: an empty label", at))
				continue
			}
			if other, dup := labels[key]; dup && other != t.Name {
				errs = append(errs, fmt.Errorf("%s: the label %q also belongs to the tier %s", at, l, other))
			}
			labels[key] = t.Name
		}
		for _, a := range t.AllowedAssigners {
			if strings.TrimSpace(a) == "" {
				errs = append(errs, fmt.Errorf("%s: an empty entry in allowed_assigners", at))
			}
		}
		for _, a := range t.Approvers {
			if strings.TrimSpace(a) == "" {
				errs = append(errs, fmt.Errorf("%s: an empty entry in approvers", at))
			}
		}
	}
	switch {
	case p.DefaultTier == "":
		errs = append(errs, errors.New("default_tier is required: the tier of a ticket that no rule matches"))
	case !seen[p.DefaultTier]:
		errs = append(errs, fmt.Errorf("default_tier: there is no tier %q", p.DefaultTier))
	}
	for i, r := range p.Rules {
		at := fmt.Sprintf("rules[%d]", i)
		if r.Source != "" && r.Source != "jira" && r.Source != "linear" {
			errs = append(errs, fmt.Errorf("%s.source must be jira, linear or empty", at))
		}
		if r.Source == "" && r.Project == "" && r.Repo == "" && r.IssueType == "" {
			errs = append(errs, fmt.Errorf("%s matches every ticket: set source, project, repo or issue_type, or use default_tier", at))
		}
		if r.Source == "linear" && r.IssueType != "" {
			errs = append(errs, fmt.Errorf("%s: a Linear issue has no issue type", at))
		}
		switch {
		case r.Tier == "":
			errs = append(errs, fmt.Errorf("%s.tier is required", at))
		case !seen[r.Tier]:
			errs = append(errs, fmt.Errorf("%s.tier: there is no tier %q", at, r.Tier))
		}
	}
	return errors.Join(errs...)
}

// CheckFile refuses a policy file that someone other than root or the user
// ochell runs as could change: by writing to it, or by putting another
// file in its place.
//
// It cannot check who the agent's OS user is. With the systemd launcher
// that is another user, who is covered by this check. With the direct
// launcher the agent runs as ochell's own user and can write whatever
// ochell can.
func CheckFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("policy %s: not a regular file", path)
	}
	if err := checkOwner(path, info); err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("policy %s: the file is writable by its group or by others (mode %04o); the agent must not be able to change the policy: chmod go-w", path, info.Mode().Perm())
	}
	dir := filepath.Dir(path)
	dinfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	// In a directory that others can write to, they can replace the file.
	// The sticky bit prevents that.
	if dinfo.Mode().Perm()&0o002 != 0 && dinfo.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("policy %s: the directory %s is writable by others, who could replace the file", path, dir)
	}
	return nil
}

// rank returns the position of a tier in the list, -1 for a name that the
// policy does not have.
func (p *Policy) rank(name string) int {
	return slices.IndexFunc(p.Tiers, func(t Tier) bool { return t.Name == name })
}

// Has reports whether the policy has a tier with this name.
func (p *Policy) Has(name string) bool { return p.rank(name) >= 0 }

// Tier returns the tier with this name. A name that the policy does not
// have (the file changed since a ticket was recorded) gives the default
// tier.
func (p *Policy) Tier(name string) Tier {
	if i := p.rank(name); i >= 0 {
		return p.Tiers[i]
	}
	return p.Tiers[p.rank(p.DefaultTier)]
}

// Next returns the tier one above the given one: where an escalation moves
// a ticket. The highest tier, and a name that the policy does not have,
// are returned as they are.
func (p *Policy) Next(name string) string {
	if i := p.rank(name); i >= 0 && i+1 < len(p.Tiers) {
		return p.Tiers[i+1].Name
	}
	return name
}

// Higher returns the higher of two tiers. A name that the policy does not
// have counts as lower than every tier.
func (p *Policy) Higher(a, b string) string {
	if p.rank(b) > p.rank(a) {
		return b
	}
	return a
}

// Ticket is what the policy looks at to find the tier of a ticket.
type Ticket struct {
	Source string
	// Project is the part of the ticket key before the number.
	Project string
	// Repo is the repository mapped to the ticket, if any.
	Repo string
	// IssueType is the Jira issue type, as far as the source said it.
	IssueType string
	Labels    []string
}

// Match returns the tier of a ticket, and why: the first rule that matches
// it, or else the default tier, raised by the labels of higher tiers that
// the ticket carries.
func (p *Policy) Match(t Ticket) (tier, why string) {
	tier, why = p.DefaultTier, "default_tier"
	for i, r := range p.Rules {
		if r.Source != "" && r.Source != t.Source {
			continue
		}
		if r.Project != "" && !strings.EqualFold(r.Project, t.Project) {
			continue
		}
		if r.Repo != "" && r.Repo != t.Repo {
			continue
		}
		if r.IssueType != "" && !strings.EqualFold(r.IssueType, t.IssueType) {
			continue
		}
		tier, why = r.Tier, fmt.Sprintf("rules[%d]", i)
		break
	}
	for i := len(p.Tiers) - 1; i > p.rank(tier); i-- {
		for _, l := range p.Tiers[i].Labels {
			if slices.ContainsFunc(t.Labels, func(have string) bool { return strings.EqualFold(strings.TrimSpace(have), strings.TrimSpace(l)) }) {
				return p.Tiers[i].Name, fmt.Sprintf("label %q", l)
			}
		}
	}
	return tier, why
}

// Describe is one line per tier, for the log and for "ochell policy-check".
func (p *Policy) Describe() []string {
	var out []string
	for _, t := range p.Tiers {
		line := fmt.Sprintf("%s: plan_gate=%s pr_review=%s auto_merge=%s", t.Name, t.PlanGate, t.PRReview, t.AutoMerge)
		if t.BudgetUSD > 0 {
			line += fmt.Sprintf(" budget_usd=%g", t.BudgetUSD)
		}
		if t.MaxTurns > 0 {
			line += fmt.Sprintf(" max_turns=%d", t.MaxTurns)
		}
		if len(t.Labels) > 0 {
			line += " labels=" + strings.Join(t.Labels, ",")
		}
		if n := len(t.AllowedAssigners); n > 0 {
			line += fmt.Sprintf(" allowed_assigners=%d", n)
		}
		if n := len(t.Approvers); n > 0 {
			line += fmt.Sprintf(" approvers=%d", n)
		}
		if t.Name == p.DefaultTier {
			line += " (default)"
		}
		out = append(out, line)
	}
	return out
}
