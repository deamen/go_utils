package workflow

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"ochell/internal/github"
	"ochell/internal/github/githubtest"
	"ochell/internal/policy"
)

const body = "Work on {{.Key}} in {{ .Repo }}.\n\n{{.RunContext}}\n\n{{.ResultInstructions}}"

func TestParse(t *testing.T) {
	f, err := Parse([]byte("---\nplan_gate: required\nmax_turns: 30\nreview_status: Code Review\nhooks:\n  before_run: [/bin/sh, -c, 'git fetch origin \"$ORCH_TASK_BRANCH\"', '{{.Key}}']\n---\n\n" + body + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f.PlanGate != "required" || f.MaxTurns != 30 || f.ReviewStatus != "Code Review" || len(f.Hooks.BeforeRun) != 4 || f.Prompt != body {
		t.Errorf("parsed %+v", f)
	}
	// Without front matter the file is a prompt; with nothing after the
	// front matter the host's prompt stays.
	if f, err := Parse([]byte(body)); err != nil || f.Prompt != body || f.PlanGate != "" {
		t.Errorf("a prompt alone: %+v, %v", f, err)
	}
	if f, err := Parse([]byte("---\r\nauto_merge: never\r\n---\r\n")); err != nil || f.Prompt != "" || f.AutoMerge != "never" {
		t.Errorf("settings alone: %+v, %v", f, err)
	}
	if f, err := Parse(nil); err != nil || f.Prompt != "" {
		t.Errorf("an empty file: %+v, %v", f, err)
	}

	for name, c := range map[string]struct{ file, want string }{
		"an unknown setting":       {"---\nplan_gat: required\n---\n", "field plan_gat not found"},
		"who may approve":          {"---\napprovers: [someone]\n---\n", "field approvers not found"},
		"a hook at the removal":    {"---\nhooks: {before_remove: [/bin/true]}\n---\n", "field before_remove not found"},
		"a value that is no value": {"---\nplan_gate: sometimes\n---\n", "plan_gate must be skip or required"},
		"negative turns":           {"---\nmax_turns: -1\n---\n", "max_turns must not be negative"},
		"front matter left open":   {"---\nplan_gate: required\n" + body, "front matter is not closed"},
		"front matter is a list":   {"---\n- a\n---\n", "front matter"},
		"a status over two lines":  {"---\nreview_status: \"a\\nb\"\n---\n", "review_status must be the name of a status"},
		"no result instructions":   {"Do {{.Key}}. {{.RunContext}}", "must include {{.ResultInstructions}}"},
		"no run context":           {"Do {{.Key}}. {{.ResultInstructions}}", "must include {{.RunContext}}"},
		"a template program":       {body + `{{range $i, $e := .Key}}{{end}}`, "is not a placeholder"},
		"a function call":          {body + `{{printf "%999999999d" 1}}`, "is not a placeholder"},
		"a field of ochell's own":  {body + "{{.Prompt}}", "{{.Prompt}} is not known here"},
		"ticket text in a hook":    {"---\nhooks: {before_run: [/bin/echo, '{{.Title}}']}\n---\n", "hooks.before_run: {{.Title}} is not known here"},
		"an empty hook command":    {"---\nhooks: {after_run: ['']}\n---\n", "hooks.after_run: the command is empty"},
		"too large":                {strings.Repeat("x", MaxSize+1), "at most"},
		"not text":                 {"\xff\xfe", "not UTF-8"},
	} {
		if _, err := Parse([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
}

// A file narrows the tier's settings; what would widen them, or what the
// host does not allow, is ignored and named, and the rest still holds.
func TestApply(t *testing.T) {
	strict := policy.Tier{Name: "high", PlanGate: "required", PRReview: "required", AutoMerge: "never", MaxTurns: 40}
	loose := policy.Tier{Name: "low", PlanGate: "skip", PRReview: "sampled", AutoMerge: "after_ci"}
	hook := []string{"/bin/true"}
	for name, c := range map[string]struct {
		file    File
		host    Host
		want    policy.Tier
		status  string
		hooks   int
		ignored []string
	}{
		"nothing set": {File{}, Host{Tier: loose}, loose, "", 0, nil},
		"narrower than a loose tier": {
			File{PlanGate: "required", PRReview: "required", AutoMerge: "never", MaxTurns: 20}, Host{Tier: loose, LimitsTurns: true},
			policy.Tier{Name: "low", PlanGate: "required", PRReview: "required", AutoMerge: "never", MaxTurns: 20}, "", 0, nil},
		"wider than a strict tier": {
			File{PlanGate: "skip", PRReview: "sampled", AutoMerge: "after_ci", MaxTurns: 80}, Host{Tier: strict, LimitsTurns: true},
			strict, "", 0, []string{"plan_gate: skip is ignored", "pr_review: sampled is ignored", "auto_merge: after_ci is ignored", "max_turns: 80 is ignored: the tier high allows 40 turns"}},
		"the same as the tier": {
			File{PlanGate: "skip", PRReview: "sampled", AutoMerge: "after_ci"}, Host{Tier: loose}, loose, "", 0, nil},
		"fewer turns than the tier": {
			File{MaxTurns: 10}, Host{Tier: strict, LimitsTurns: true},
			policy.Tier{Name: "high", PlanGate: "required", PRReview: "required", AutoMerge: "never", MaxTurns: 10}, "", 0, nil},
		"turns that nothing can enforce": {
			File{MaxTurns: 10}, Host{Tier: loose}, loose, "", 0, []string{"max_turns: 10 is ignored: the agent adapter cannot stop a run at a limit"}},
		"a status the host lists": {
			File{ReviewStatus: "code review"}, Host{Tier: loose, ReviewStatuses: []string{"In Review", "Code Review"}}, loose, "Code Review", 0, nil},
		"a status the host does not list": {
			File{ReviewStatus: "Done"}, Host{Tier: loose, ReviewStatuses: []string{"In Review"}}, loose, "", 0, []string{`review_status: "Done" is ignored`}},
		"hooks the host allows": {
			File{Hooks: Hooks{AfterCreate: hook, BeforeRun: hook, AfterRun: hook}}, Host{Tier: loose, AllowHooks: true}, loose, "", 3, nil},
		"hooks the host does not allow": {
			File{Hooks: Hooks{BeforeRun: hook, AfterRun: hook}, PlanGate: "required"}, Host{Tier: loose},
			policy.Tier{Name: "low", PlanGate: "required", PRReview: "sampled", AutoMerge: "after_ci"}, "", 0,
			[]string{"hooks.before_run is ignored: the host does not run a repository's hooks", "hooks.after_run is ignored"}},
	} {
		c.file.Prompt = body
		e := c.file.Apply(c.host)
		hooks := 0
		for _, h := range e.Hooks.All() {
			if len(h.Command) > 0 {
				hooks++
			}
		}
		if e.Tier.Name != c.want.Name || e.Tier.PlanGate != c.want.PlanGate || e.Tier.PRReview != c.want.PRReview || e.Tier.AutoMerge != c.want.AutoMerge ||
			e.Tier.MaxTurns != c.want.MaxTurns || e.ReviewStatus != c.status || hooks != c.hooks || e.Prompt != body {
			t.Errorf("%s: %+v", name, e)
		}
		if len(e.Ignored) != len(c.ignored) {
			t.Errorf("%s: ignored %q, want %q", name, e.Ignored, c.ignored)
			continue
		}
		for i, want := range c.ignored {
			if !strings.Contains(e.Ignored[i], want) {
				t.Errorf("%s: ignored[%d] = %q, want it to say %q", name, i, e.Ignored[i], want)
			}
		}
	}
	// No file: the tier as it is.
	var none *File
	if e := none.Apply(Host{Tier: strict}); e.Tier.PlanGate != "required" || e.Prompt != "" || e.Ignored != nil {
		t.Errorf("no file: %+v", e)
	}
}

// The file is read from the default branch of the repository on GitHub.
func TestGitHubSource(t *testing.T) {
	gh := githubtest.New(t)
	src := GitHub{Client: github.New(gh.URL, githubtest.Token)}
	repo := "http://" + gh.Host() + "/example/web.git"
	ctx := context.Background()

	gh.SetFile("example", "web", FileName, body)
	raw, v1, found, err := src.Read(ctx, repo)
	if err != nil || !found || string(raw) != body || !strings.HasPrefix(v1, "sha:") {
		t.Fatalf("read: %q %q %v %v", raw, v1, found, err)
	}
	gh.SetFile("example", "web", FileName, body+"\nMore.")
	if _, v2, _, err := src.Read(ctx, repo); err != nil || v2 == v1 {
		t.Errorf("the version did not change with the content: %q, %v", v2, err)
	}
	// A repository without the file is not an error.
	gh.RemoveFile("example", "web", FileName)
	if _, _, found, err := src.Read(ctx, repo); err != nil || found {
		t.Errorf("a repository without the file: found %v, %v", found, err)
	}
	// A repository that the token cannot see is: the file is not known
	// to be gone.
	if _, _, _, err := src.Read(ctx, "http://"+gh.Host()+"/example/hidden.git"); err == nil || errors.Is(err, ErrElsewhere) || !strings.Contains(err.Error(), "does not show example/hidden") {
		t.Errorf("a hidden repository: %v", err)
	}
	if _, _, _, err := src.Read(ctx, "git@gitlab.example:example/web.git"); !errors.Is(err, ErrElsewhere) {
		t.Errorf("a repository on another host: %v", err)
	}
	// Too large a file is an error of the read, so the last good stays.
	gh.SetFile("example", "web", FileName, strings.Repeat("x", MaxSize+1))
	if _, _, _, err := src.Read(ctx, repo); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("a large file: %v", err)
	}
}

// The example file is valid, and narrows the built-in tier.
func TestExampleFile(t *testing.T) {
	raw, err := os.ReadFile("../../examples/WORKFLOW.md")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	e := f.Apply(Host{Tier: policy.Builtin().Tiers[0], AllowHooks: true, ReviewStatuses: []string{"Code Review"}, LimitsTurns: true})
	if e.Tier.PlanGate != "required" || e.Tier.MaxTurns != 60 || e.ReviewStatus != "Code Review" || len(e.Hooks.AfterCreate) == 0 || e.Prompt == "" || len(e.Ignored) != 0 {
		t.Errorf("the example: %+v", e)
	}
}
