// Package workflow reads WORKFLOW.md, the file in which a repository says
// how tickets are worked in it: the prompt, workspace hooks, the status of
// the hand-over, and limits that are stricter than the host's.
//
// The file is untrusted. It is in a repository that the agent pushes to,
// so ochell reads it from the default branch only (source.go), where a
// change is one that a person merged, and even then it can only narrow the
// host's policy: a setting that would give a ticket more than its tier
// does is ignored and reported (Apply). Tiers and who may assign
// or approve are not settings of this file at all.
package workflow

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"ochell/internal/policy"
)

// FileName is the name of the file, at the top of the repository.
const FileName = "WORKFLOW.md"

// MaxSize is how large the file may be.
const MaxSize = 64 << 10

// Hooks are the hooks that a repository adds to the host's. Each is a
// command with its arguments, as in workspace.hooks. There is no
// before_remove: a working directory is removed outside any run, by the
// host alone.
type Hooks struct {
	AfterCreate []string `yaml:"after_create"`
	BeforeRun   []string `yaml:"before_run"`
	AfterRun    []string `yaml:"after_run"`
}

// All returns the hooks by name, in the order they run.
func (h Hooks) All() []struct {
	Name    string
	Command []string
} {
	return []struct {
		Name    string
		Command []string
	}{{"after_create", h.AfterCreate}, {"before_run", h.BeforeRun}, {"after_run", h.AfterRun}}
}

// Command returns the hook with this name, or nil.
func (h Hooks) Command(name string) []string {
	for _, c := range h.All() {
		if c.Name == name {
			return c.Command
		}
	}
	return nil
}

// File is the content of a WORKFLOW.md: the settings of its front matter,
// and the prompt, which is the rest of the file.
type File struct {
	// PlanGate, PRReview and AutoMerge are the tier's settings of the same
	// names; empty: the tier's own value.
	PlanGate  string `yaml:"plan_gate"`
	PRReview  string `yaml:"pr_review"`
	AutoMerge string `yaml:"auto_merge"`
	// MaxTurns is how many turns one run may take; 0: the tier's own limit.
	MaxTurns int `yaml:"max_turns"`
	// ReviewStatus is the Jira status a ticket is moved to at the
	// hand-over; empty: the host's.
	ReviewStatus string `yaml:"review_status"`
	Hooks        Hooks  `yaml:"hooks"`

	// Prompt is the prompt template; empty: the host's.
	Prompt string `yaml:"-"`
}

// What the templates of a file may name. A file's templates are not Go
// templates: only these placeholders, written {{.Name}}, are replaced, so
// that text from a repository is never run as a template program.
var (
	PromptFields = []string{"Source", "Key", "Title", "URL", "Repo", "Context", "ID", "Attempt", "ResultFile", "ResultInstructions", "RunContext"}
	HookFields   = []string{"ID", "Source", "Key", "Repo", "Branch"}
)

var placeholder = regexp.MustCompile(`^\{\{ *\.([A-Za-z]+) *\}\}`)

// placeholders checks that every "{{" in text starts a placeholder with one
// of the allowed names, and returns the names that are used.
func placeholders(text string, allowed []string) ([]string, error) {
	var used []string
	for rest := text; ; {
		i := strings.Index(rest, "{{")
		if i < 0 {
			return used, nil
		}
		rest = rest[i:]
		m := placeholder.FindStringSubmatch(rest)
		if m == nil {
			at := rest
			if len(at) > 30 {
				at = strings.ToValidUTF8(at[:30], "") + "…"
			}
			return nil, fmt.Errorf("%q is not a placeholder: only {{.Name}} is replaced, with one of %s", at, strings.Join(allowed, ", "))
		}
		if !slices.Contains(allowed, m[1]) {
			return nil, fmt.Errorf("{{.%s}} is not known here: use one of %s", m[1], strings.Join(allowed, ", "))
		}
		used = append(used, m[1])
		rest = rest[len(m[0]):]
	}
}

// Parse reads and checks the content of a WORKFLOW.md: YAML front matter
// between two lines of "---", and after it the prompt. A file without
// front matter is a prompt and nothing else.
//
// A setting that ochell does not know is an error, as in the policy file:
// the whole file is then invalid.
func Parse(raw []byte) (*File, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("the file has %d bytes; at most %d are read", len(raw), MaxSize)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("the file is not UTF-8 text")
	}
	text := strings.ReplaceAll(strings.TrimPrefix(string(raw), "\ufeff"), "\r\n", "\n")
	var f File
	if first, rest, _ := strings.Cut(text, "\n"); strings.TrimRight(first, " \t") == "---" {
		front, body, closed := "", "", false
		for rest != "" {
			var line string
			line, rest, _ = strings.Cut(rest, "\n")
			if strings.TrimRight(line, " \t") == "---" {
				body, closed = rest, true
				break
			}
			front += line + "\n"
		}
		if !closed {
			return nil, errors.New(`the front matter is not closed: it ends with a line of "---"`)
		}
		dec := yaml.NewDecoder(bytes.NewReader([]byte(front)))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("front matter: %w", err)
		}
		text = body
	}
	f.Prompt = strings.TrimSpace(text)
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *File) validate() error {
	var errs []error
	if f.PlanGate != "" && f.PlanGate != policy.PlanGateSkip && f.PlanGate != policy.PlanGateRequired {
		errs = append(errs, errors.New("plan_gate must be skip or required"))
	}
	if f.PRReview != "" && f.PRReview != policy.PRReviewRequired && f.PRReview != policy.PRReviewSampled {
		errs = append(errs, errors.New("pr_review must be required or sampled"))
	}
	if f.AutoMerge != "" && f.AutoMerge != policy.AutoMergeNever && f.AutoMerge != policy.AutoMergeAfterCI {
		errs = append(errs, errors.New("auto_merge must be never or after_ci"))
	}
	if f.MaxTurns < 0 {
		errs = append(errs, errors.New("max_turns must not be negative; leave it out for the tier's own limit"))
	}
	if s := f.ReviewStatus; s != strings.TrimSpace(s) || len(s) > 100 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		errs = append(errs, errors.New("review_status must be the name of a status: one line of at most 100 characters"))
	}
	for _, h := range f.Hooks.All() {
		if len(h.Command) == 0 {
			continue
		}
		if h.Command[0] == "" {
			errs = append(errs, fmt.Errorf("hooks.%s: the command is empty", h.Name))
		}
		for _, a := range h.Command {
			if _, err := placeholders(a, HookFields); err != nil {
				errs = append(errs, fmt.Errorf("hooks.%s: %w", h.Name, err))
			}
		}
	}
	if f.Prompt != "" {
		used, err := placeholders(f.Prompt, PromptFields)
		if err != nil {
			errs = append(errs, fmt.Errorf("prompt: %w", err))
		}
		// As for the host's template: without these no agent reports its
		// result, and a later attempt knows nothing of the earlier ones or
		// of a plan gate.
		for _, need := range []string{"RunContext", "ResultInstructions"} {
			if err == nil && !slices.Contains(used, need) {
				errs = append(errs, fmt.Errorf("prompt: it must include {{.%s}}", need))
			}
		}
	}
	return errors.Join(errs...)
}

// Host is what the host allows a repository's file, for one ticket.
type Host struct {
	// Tier is the ticket's tier, as the policy file has it.
	Tier policy.Tier
	// AllowHooks says that a repository may add hooks (workflow.allow_hooks).
	AllowHooks bool
	// ReviewStatuses are the statuses that a repository may choose from
	// for the hand-over (workflow.review_statuses).
	ReviewStatuses []string
	// LimitsTurns says that the agent adapter can stop a run at a number
	// of turns.
	LimitsTurns bool
}

// Effective is what holds for a run: the host's policy, narrowed by the
// repository's file.
type Effective struct {
	// Tier is the ticket's tier with the file's stricter settings.
	Tier policy.Tier
	// Prompt is the repository's prompt template; empty: the host's.
	Prompt string
	// Hooks run after the host's hooks of the same name.
	Hooks Hooks
	// ReviewStatus takes the place of the host's; empty: the host's.
	ReviewStatus string
	// Ignored names each setting of the file that was not used, and why.
	Ignored []string
}

// AllowedStatus returns the entry of allowed that status names, or "".
func AllowedStatus(status string, allowed []string) string {
	for _, a := range allowed {
		if status != "" && strings.EqualFold(strings.TrimSpace(a), status) {
			return strings.TrimSpace(a)
		}
	}
	return ""
}

// Apply narrows the host's policy for one ticket by the file. A nil file
// changes nothing.
//
// What narrowing means, per setting:
//   - plan_gate: required is stricter than skip;
//   - pr_review: required is stricter than sampled;
//   - auto_merge: never is stricter than after_ci;
//   - max_turns: a lower number is stricter, and any number is stricter
//     than no limit;
//   - review_status: one of the statuses the host lists, and no other;
//   - hooks: only when the host allows a repository's hooks; they are run
//     in addition to the host's, never in their place;
//   - the prompt: text for the agent, which gives it no access.
//
// A setting that is not stricter than the tier's, or that the host does
// not allow, is left out and named in Ignored. The rest of the file holds.
func (f *File) Apply(h Host) Effective {
	e := Effective{Tier: h.Tier}
	if f == nil {
		return e
	}
	ignore := func(format string, args ...any) {
		e.Ignored = append(e.Ignored, fmt.Sprintf(format, args...))
	}
	t := h.Tier
	const only = "a repository's file can only narrow the policy"
	switch {
	case f.PlanGate == policy.PlanGateRequired:
		e.Tier.PlanGate = policy.PlanGateRequired
	case f.PlanGate == policy.PlanGateSkip && t.PlanGate == policy.PlanGateRequired:
		ignore("plan_gate: skip is ignored: the tier %s requires an approved plan, and %s", t.Name, only)
	}
	switch {
	case f.PRReview == policy.PRReviewRequired:
		e.Tier.PRReview = policy.PRReviewRequired
	case f.PRReview == policy.PRReviewSampled && t.PRReview == policy.PRReviewRequired:
		ignore("pr_review: sampled is ignored: the tier %s requires a review of every pull request, and %s", t.Name, only)
	}
	switch {
	case f.AutoMerge == policy.AutoMergeNever:
		e.Tier.AutoMerge = policy.AutoMergeNever
	case f.AutoMerge == policy.AutoMergeAfterCI && t.AutoMerge == policy.AutoMergeNever:
		ignore("auto_merge: after_ci is ignored: the tier %s never merges without a person, and %s", t.Name, only)
	}
	switch {
	case f.MaxTurns == 0:
	case !h.LimitsTurns:
		ignore("max_turns: %d is ignored: the agent adapter cannot stop a run at a limit (it needs agent.adapter claude)", f.MaxTurns)
	case t.MaxTurns > 0 && f.MaxTurns > t.MaxTurns:
		ignore("max_turns: %d is ignored: the tier %s allows %d turns, and %s", f.MaxTurns, t.Name, t.MaxTurns, only)
	default:
		e.Tier.MaxTurns = f.MaxTurns
	}
	if f.ReviewStatus != "" {
		if e.ReviewStatus = AllowedStatus(f.ReviewStatus, h.ReviewStatuses); e.ReviewStatus == "" {
			ignore("review_status: %q is ignored: it is not one of the statuses that the host lets a repository choose (workflow.review_statuses)", f.ReviewStatus)
		}
	}
	for _, hk := range f.Hooks.All() {
		switch {
		case len(hk.Command) == 0:
			continue
		case !h.AllowHooks:
			ignore("hooks.%s is ignored: the host does not run a repository's hooks (workflow.allow_hooks)", hk.Name)
			continue
		}
		switch hk.Name {
		case "after_create":
			e.Hooks.AfterCreate = hk.Command
		case "before_run":
			e.Hooks.BeforeRun = hk.Command
		case "after_run":
			e.Hooks.AfterRun = hk.Command
		}
	}
	e.Prompt = f.Prompt
	return e
}
