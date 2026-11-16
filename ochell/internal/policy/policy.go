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
	"time"

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
	// Grants are the tools and credentials that a run of this tier gets,
	// on top of what every run has.
	Grants Grants `yaml:"grants"`
	// Paused holds the tickets of this tier: none of them starts. It is
	// the setting in the file; "ochell pause --tier" does the same on a
	// running ochell.
	Paused bool `yaml:"paused"`
	// MaxConcurrent is how many tickets of this tier may have an agent
	// running at the same time; 0: no limit of its own.
	MaxConcurrent int `yaml:"max_concurrent"`
}

// Grants are the tools and credentials of the runs of one tier.
type Grants struct {
	// MCPConfig is a file with the MCP servers of the tier, in the format
	// of the agent CLI. The agent must be able to read it. A run of the
	// tier gets these servers and no others.
	MCPConfig string `yaml:"mcp_config"`
	// Env is set in the agent's environment. It is not for secrets: with
	// the systemd launcher other local users can read it.
	Env map[string]string `yaml:"env"`
	// CredentialsFile holds secrets as NAME=VALUE lines, which are put in
	// the agent's environment without being visible to other users. The
	// file is ochell's own: nobody else may read it.
	CredentialsFile string `yaml:"credentials_file"`
	// Mint is a command that ochell runs before each run of the tier, to
	// get credentials that are made for that run: it prints NAME=VALUE
	// lines. Revoke is the command that ochell runs when the run has
	// ended, with those variables in its environment, to make them
	// useless. Both are run by ochell itself, not as the agent.
	Mint   []string `yaml:"mint"`
	Revoke []string `yaml:"revoke"`
	// TicketTools gives a run ochell's ticket tools: it reads and comments
	// on its ticket through ochell's own MCP server, and needs no tracker
	// token for that. The host must have them turned on (ticket_tools in
	// the configuration).
	TicketTools bool `yaml:"ticket_tools"`
}

// TicketToolsRefs are what the MCP configuration of a tier with the ticket
// tools must refer to: the address of ochell's server and the token of the
// run, which the agent CLI replaces from the run's environment. The token
// is never in a file.
var TicketToolsRefs = []string{"${ORCH_TOOLS_URL}", "${ORCH_TOOLS_TOKEN}"}

// Empty reports whether the tier grants nothing.
func (g Grants) Empty() bool {
	return g.MCPConfig == "" && len(g.Env) == 0 && g.CredentialsFile == "" && len(g.Mint) == 0 && !g.TicketTools
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validate checks what can be checked without looking at the file system.
func (g Grants) validate(at string) []error {
	var errs []error
	for name, path := range map[string]string{"mcp_config": g.MCPConfig, "credentials_file": g.CredentialsFile} {
		if path != "" && !filepath.IsAbs(path) {
			errs = append(errs, fmt.Errorf("%s: grants.%s must be an absolute path", at, name))
		}
	}
	for n := range g.Env {
		switch {
		case !envName.MatchString(n):
			errs = append(errs, fmt.Errorf("%s: grants.env: %q is not a variable name", at, n))
		case strings.HasPrefix(n, "ORCH_"):
			errs = append(errs, fmt.Errorf("%s: grants.env: %s: names that start with ORCH_ are ochell's own", at, n))
		}
	}
	for name, cmd := range map[string][]string{"mint": g.Mint, "revoke": g.Revoke} {
		if len(cmd) > 0 && !filepath.IsAbs(cmd[0]) {
			errs = append(errs, fmt.Errorf("%s: grants.%s: the command must be an absolute path", at, name))
		}
	}
	if len(g.Revoke) > 0 && len(g.Mint) == 0 {
		errs = append(errs, fmt.Errorf("%s: grants.revoke without grants.mint: there is nothing to revoke", at))
	}
	return errs
}

// ReadCredentials reads a credentials file: NAME=VALUE lines, with empty
// lines and lines that start with # left out. It refuses a file that
// anyone but its owner can read, or that belongs to another user than root
// or the one ochell runs as: the agent must not get at the credentials of
// another tier.
func ReadCredentials(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if err := checkOwner(path, info); err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: the file can be read or written by its group or by others (mode %04o); it holds secrets: chmod 600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCredentials(string(raw), path)
}

// ParseCredentials reads NAME=VALUE lines, as a credentials file and the
// output of a mint command have them. from names the source in errors; a
// value is never part of an error.
func ParseCredentials(text, from string) ([]string, error) {
	var out []string
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		switch {
		case !ok || !envName.MatchString(name):
			return nil, fmt.Errorf("%s: line %d is not NAME=VALUE", from, i+1)
		case strings.HasPrefix(name, "ORCH_"):
			return nil, fmt.Errorf("%s: line %d: names that start with ORCH_ are ochell's own", from, i+1)
		case value == "":
			return nil, fmt.Errorf("%s: line %d: %s has no value", from, i+1, name)
		case strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			return nil, fmt.Errorf("%s: line %d: the value of %s has a control character", from, i+1, name)
		}
		out = append(out, name+"="+value)
	}
	return out, nil
}

// checkGrants checks the files that the grants name. Load calls it; Parse
// does not, so a policy can be parsed without its files.
func (p *Policy) checkGrants() error {
	var errs []error
	for _, t := range p.Tiers {
		g := t.Grants
		if g.MCPConfig != "" {
			if info, err := os.Stat(g.MCPConfig); err != nil || !info.Mode().IsRegular() {
				errs = append(errs, fmt.Errorf("tier %s: grants.mcp_config %s is not a file that ochell can see (%v)", t.Name, g.MCPConfig, err))
			} else if g.TicketTools {
				// With mcp_config the agent gets the servers of that file
				// and no others, so ochell's own has to be in it.
				raw, err := os.ReadFile(g.MCPConfig)
				for _, ref := range TicketToolsRefs {
					if err != nil || !strings.Contains(string(raw), ref) {
						errs = append(errs, fmt.Errorf("tier %s: grants.ticket_tools: grants.mcp_config %s does not name ochell's server: it needs an entry with %s (see examples/mcp-ticket-tools.json)", t.Name, g.MCPConfig, ref))
						break
					}
				}
			}
		}
		if g.CredentialsFile != "" {
			if _, err := ReadCredentials(g.CredentialsFile); err != nil {
				errs = append(errs, fmt.Errorf("tier %s: grants.credentials_file: %w", t.Name, err))
			}
		}
		for name, cmd := range map[string][]string{"mint": g.Mint, "revoke": g.Revoke} {
			if len(cmd) == 0 {
				continue
			}
			if info, err := os.Stat(cmd[0]); err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
				errs = append(errs, fmt.Errorf("tier %s: grants.%s: %s is not a program that ochell can run (%v)", t.Name, name, cmd[0], err))
			}
		}
	}
	return errors.Join(errs...)
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
	// Paused holds every ticket: no run starts. It is the setting in the
	// file; "ochell pause" does the same on a running ochell.
	Paused bool `yaml:"paused"`
	// Throttles bound what ochell starts, over all tiers.
	Throttles Throttles `yaml:"throttles"`
	// Scheduling says which queued ticket starts next, and which waits.
	Scheduling Scheduling `yaml:"scheduling"`
	// Autonomy gives the classes of work a level of autonomy, which holds
	// back what a tier allows until an operator has promoted the class.
	Autonomy Autonomy `yaml:"autonomy"`

	// File is where the policy was read from; empty for the built-in one.
	File string `yaml:"-"`
}

// Throttles hold new runs back when a limit is reached. Runs that are
// going on are not touched. 0 means no limit.
type Throttles struct {
	// MaxRunsPerHour is how many runs may start within one hour.
	MaxRunsPerHour int `yaml:"max_runs_per_hour"`
	// MaxOpenPRsPerRepo is how many pull requests of the bot may be open
	// in one repository. A ticket that would open another one is held.
	MaxOpenPRsPerRepo int `yaml:"max_open_prs_per_repo"`
	// DailySpendUSD is what the runs of one day (UTC) may cost in total.
	DailySpendUSD float64 `yaml:"daily_spend_usd"`
}

// Values of scheduling.blocked_by.
const (
	BlockedByIgnore = "ignore"
	BlockedByWait   = "wait"
)

// DefaultCheckInterval is how often ochell asks the tracker about the
// tickets that scheduling holds, unless the policy says otherwise.
const DefaultCheckInterval = time.Minute

// Scheduling says which queued ticket starts next, and which waits. The
// queue is always ordered by the priority that the tracker gives a ticket,
// and by age within one priority.
//
// The gates (required_labels, blocked_by) hold the start of the work on a
// ticket: the run of an assignment. A run that continues the work (a
// retry, a follow-up, an approved plan) is not held by them.
type Scheduling struct {
	// MaxConcurrentPerRepo is how many tickets of one repository may have
	// an agent running at the same time; 0: no limit.
	MaxConcurrentPerRepo int `yaml:"max_concurrent_per_repo"`
	// RequiredLabels are labels that a ticket must carry before its work
	// starts: every one of them, each put there by someone other than
	// the bot account.
	RequiredLabels []string `yaml:"required_labels"`
	// BlockedBy is "wait" when a ticket that the tracker calls blocked
	// by another, open ticket waits until that one is done, and "ignore"
	// otherwise.
	BlockedBy string `yaml:"blocked_by"`
	// CheckInterval is how often ochell asks the tracker about the
	// tickets that a gate holds.
	CheckInterval time.Duration `yaml:"check_interval"`
	// Priorities maps the name of a priority in Jira to its rank, from 1
	// (the most urgent) to 5. It adds to the names that ochell knows, and
	// takes the place of one of them.
	Priorities map[string]int `yaml:"priorities"`
}

// Gated reports whether a ticket has to pass a gate before its work
// starts. A gate is checked against the tracker.
func (s Scheduling) Gated() bool {
	return len(s.RequiredLabels) > 0 || s.BlockedBy == BlockedByWait
}

// jiraPriorities are the ranks of the priority names that Jira comes with,
// today's and the older ones.
var jiraPriorities = map[string]int{
	"highest": 1, "high": 2, "medium": 3, "low": 4, "lowest": 5,
	"blocker": 1, "critical": 2, "major": 3, "minor": 4, "trivial": 5,
}

// Rank returns the rank of a priority by its name in Jira, from 1 (the
// most urgent) to 5, and 0 for a name that is not known: such a ticket
// has no priority for ochell.
func (s Scheduling) Rank(name string) int {
	name = strings.ToLower(strings.TrimSpace(name))
	for n, rank := range s.Priorities {
		if strings.ToLower(strings.TrimSpace(n)) == name {
			return rank
		}
	}
	return jiraPriorities[name]
}

// Missing returns the required labels that are not among have.
func (s Scheduling) Missing(have []string) []string {
	var missing []string
	for _, want := range s.RequiredLabels {
		if !slices.ContainsFunc(have, func(l string) bool { return strings.EqualFold(strings.TrimSpace(l), strings.TrimSpace(want)) }) {
			missing = append(missing, strings.TrimSpace(want))
		}
	}
	return missing
}

// validate checks the scheduling settings.
func (s Scheduling) validate() []error {
	var errs []error
	if s.MaxConcurrentPerRepo < 0 {
		errs = append(errs, errors.New("scheduling.max_concurrent_per_repo must not be negative; 0 means no limit"))
	}
	if s.BlockedBy != BlockedByIgnore && s.BlockedBy != BlockedByWait {
		errs = append(errs, errors.New("scheduling.blocked_by must be ignore or wait"))
	}
	if s.CheckInterval <= 0 {
		errs = append(errs, errors.New("scheduling.check_interval must be more than 0"))
	}
	seen := map[string]bool{}
	for _, l := range s.RequiredLabels {
		key := strings.ToLower(strings.TrimSpace(l))
		switch {
		case key == "":
			errs = append(errs, errors.New("scheduling.required_labels: an empty label"))
		case seen[key]:
			errs = append(errs, fmt.Errorf("scheduling.required_labels: the label %q is listed twice", l))
		}
		seen[key] = true
	}
	names := map[string]bool{}
	for name, rank := range s.Priorities {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" || rank < 1 || rank > 5 {
			errs = append(errs, fmt.Errorf("scheduling.priorities: %q: a priority has a name and a rank from 1 (the most urgent) to 5", name))
		}
		// Upper and lower case are not told apart, so two spellings of
		// one name could say two things.
		if names[key] {
			errs = append(errs, fmt.Errorf("scheduling.priorities: the priority %q is listed twice", name))
		}
		names[key] = true
	}
	return errs
}

// Builtin is the policy of an ochell that has no policy file: one tier,
// under which every ticket runs as it did before there were tiers.
func Builtin() *Policy {
	return &Policy{
		Version:     "builtin",
		Tiers:       []Tier{{Name: DefaultTierName, PlanGate: PlanGateSkip, PRReview: PRReviewRequired, AutoMerge: AutoMergeNever}},
		DefaultTier: DefaultTierName,
		Scheduling:  Scheduling{BlockedBy: BlockedByIgnore, CheckInterval: DefaultCheckInterval},
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
	if err := p.checkGrants(); err != nil {
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
	if p.Scheduling.BlockedBy == "" {
		p.Scheduling.BlockedBy = BlockedByIgnore
	}
	if p.Scheduling.CheckInterval == 0 {
		p.Scheduling.CheckInterval = DefaultCheckInterval
	}
	p.Autonomy.setDefaults()
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
	if th := p.Throttles; th.MaxRunsPerHour < 0 || th.MaxOpenPRsPerRepo < 0 || th.DailySpendUSD < 0 {
		errs = append(errs, errors.New("throttles: a limit must not be negative; 0 means no limit"))
	}
	errs = append(errs, p.Scheduling.validate()...)
	errs = append(errs, p.Autonomy.validate()...)
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
		if t.MaxConcurrent < 0 {
			errs = append(errs, fmt.Errorf("%s: max_concurrent must not be negative; 0 means no limit", at))
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
		errs = append(errs, t.Grants.validate(at)...)
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
// that is another user, who is covered by this check, and with the podman
// launcher the file is not in the agent's container. With the direct
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
		if g := t.Grants; !g.Empty() {
			var what []string
			if g.MCPConfig != "" {
				what = append(what, "mcp_config")
			}
			if len(g.Env) > 0 {
				what = append(what, "env")
			}
			if g.CredentialsFile != "" {
				what = append(what, "credentials_file")
			}
			if len(g.Mint) > 0 {
				what = append(what, "mint")
			}
			if g.TicketTools {
				what = append(what, "ticket_tools")
			}
			line += " grants=" + strings.Join(what, "+")
		}
		if n := len(t.Approvers); n > 0 {
			line += fmt.Sprintf(" approvers=%d", n)
		}
		if t.MaxConcurrent > 0 {
			line += fmt.Sprintf(" max_concurrent=%d", t.MaxConcurrent)
		}
		if t.Paused {
			line += " paused"
		}
		if t.Name == p.DefaultTier {
			line += " (default)"
		}
		out = append(out, line)
	}
	return out
}

// DescribeScheduling is one line per scheduling setting that is set, for
// the log and for "ochell policy-check".
func (p *Policy) DescribeScheduling() []string {
	s := p.Scheduling
	var out []string
	if s.MaxConcurrentPerRepo > 0 {
		out = append(out, fmt.Sprintf("max_concurrent_per_repo=%d", s.MaxConcurrentPerRepo))
	}
	if len(s.RequiredLabels) > 0 {
		out = append(out, "required_labels="+strings.Join(s.RequiredLabels, ","))
	}
	if s.BlockedBy == BlockedByWait {
		out = append(out, "blocked_by=wait")
	}
	if s.Gated() {
		out = append(out, "check_interval="+s.CheckInterval.String())
	}
	return out
}
