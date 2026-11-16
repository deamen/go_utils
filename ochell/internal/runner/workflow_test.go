package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"ochell/internal/config"
	"ochell/internal/policy"
	"ochell/internal/task"
	"ochell/internal/workflow"
)

// fakeSource is the default branch of one repository, as a test sets it.
type fakeSource struct {
	mu      sync.Mutex
	content string
	version string
	gone    bool
	err     error
}

func (f *fakeSource) set(version, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version, f.content, f.gone, f.err = version, content, false, nil
}

func (f *fakeSource) Read(_ context.Context, repo string) ([]byte, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case repo != testRepo:
		return nil, "", false, workflow.ErrElsewhere
	case f.err != nil:
		return nil, "", false, f.err
	case f.gone:
		return nil, "", false, nil
	}
	return []byte(f.content), f.version, true, nil
}

const (
	testRepo   = "git@github.com:example/web.git"
	promptTail = "\n{{.RunContext}}\n{{.ResultInstructions}}\n"
)

// runRepo submits a task for DEV-1 with the test repository and waits for
// its run to end. It returns the result and the log of the run.
func (w *workspaceRunner) runRepo(t *testing.T, id string) (task.Result, string) {
	t.Helper()
	tk := newTask()
	tk.ID, tk.Repo = id, testRepo
	if err := w.Submit(tk); err != nil {
		t.Fatal(err)
	}
	w.done.wait(t, "DEV-1")
	res := w.done.result("DEV-1")
	logged, _ := os.ReadFile(res.LogFile)
	return res, string(logged)
}

// A change of the file takes effect with the next run. A file that is
// invalid or cannot be read leaves the last good one in force, and one that
// is gone gives the host's settings back.
func TestWorkflowIsReadForEveryRun(t *testing.T) {
	src := &fakeSource{}
	src.set("v1", "Rules of the repository, first version, for {{.Key}}."+promptTail)
	w := newWorkspaceRunner(t, config.Workspace{}, func(r *Runner) { r.UseWorkflow(config.Workflow{Enabled: true}, src) })
	status := func() WorkflowStatus {
		t.Helper()
		st, err := w.Status()
		if err != nil || len(st.Workflows) != 1 || st.Workflows[0].Repo != testRepo {
			t.Fatalf("status: %+v, %v", st, err)
		}
		return st.Workflows[0]
	}

	res, logged := w.runRepo(t, "t1")
	if res.Workflow != "v1" || !strings.Contains(logged, "Rules of the repository, first version, for DEV-1.") || strings.Contains(logged, "Fix DEV-1") ||
		!strings.Contains(logged, "# workflow=v1 (WORKFLOW.md of "+testRepo+", from its default branch)") {
		t.Errorf("first run: workflow %q, log:\n%s", res.Workflow, logged)
	}
	if !strings.Contains(logged, "ORCH_RESULT_FILE") {
		t.Errorf("the repository's prompt lost the result instructions:\n%s", logged)
	}
	if st := status(); st.Version != "v1" || st.Error != "" || st.Loaded == nil {
		t.Errorf("status after the first run: %+v", st)
	}

	src.set("v2", "---\nplan_gate: skip\n---\nRules of the repository, second version."+promptTail)
	if res, logged = w.runRepo(t, "t2"); res.Workflow != "v2" || !strings.Contains(logged, "second version") {
		t.Errorf("after a change: workflow %q, log:\n%s", res.Workflow, logged)
	}

	// Invalid: a setting that ochell does not know.
	src.set("v3", "---\nbudget_usd: 1000\n---\nRules of the repository, third version."+promptTail)
	if res, logged = w.runRepo(t, "t3"); res.Workflow != "v2" || !strings.Contains(logged, "second version") || strings.Contains(logged, "third version") ||
		!strings.Contains(logged, "# workflow: WORKFLOW.md on the default branch (v3) is invalid") {
		t.Errorf("after an invalid change: workflow %q, log:\n%s", res.Workflow, logged)
	}
	if st := status(); st.Version != "v2" || !strings.Contains(st.Error, "field budget_usd not found") || !strings.Contains(st.Error, "the last good version (v2) stays in force") {
		t.Errorf("status with an invalid file: %+v", st)
	}

	// Not readable: the same.
	src.mu.Lock()
	src.err = errors.New("github api: HTTP 502")
	src.mu.Unlock()
	if res, logged = w.runRepo(t, "t4"); res.Workflow != "v2" || !strings.Contains(logged, "second version") {
		t.Errorf("when the file cannot be read: workflow %q, log:\n%s", res.Workflow, logged)
	}
	if st := status(); !strings.Contains(st.Error, "could not be read from the default branch: github api: HTTP 502") {
		t.Errorf("status when the file cannot be read: %+v", st)
	}

	// Fixed: the error is gone.
	src.set("v4", "Rules of the repository, fourth version."+promptTail)
	if res, logged = w.runRepo(t, "t5"); res.Workflow != "v4" || !strings.Contains(logged, "fourth version") {
		t.Errorf("after the fix: workflow %q, log:\n%s", res.Workflow, logged)
	}
	if st := status(); st.Version != "v4" || st.Error != "" {
		t.Errorf("status after the fix: %+v", st)
	}

	// Taken off the default branch: the host's prompt again.
	src.mu.Lock()
	src.gone = true
	src.mu.Unlock()
	if res, logged = w.runRepo(t, "t6"); res.Workflow != "" || !strings.Contains(logged, "Fix DEV-1") || strings.Contains(logged, "fourth version") {
		t.Errorf("without the file: workflow %q, log:\n%s", res.Workflow, logged)
	}
	if st := status(); st.Version != "" || st.Error != "" || st.Loaded != nil {
		t.Errorf("status without the file: %+v", st)
	}
}

// An invalid file with no good one before it leaves the host's settings.
func TestWorkflowInvalidFromTheStart(t *testing.T) {
	src := &fakeSource{}
	src.set("v1", "A prompt without what ochell needs in it.")
	w := newWorkspaceRunner(t, config.Workspace{}, func(r *Runner) { r.UseWorkflow(config.Workflow{Enabled: true}, src) })
	res, logged := w.runRepo(t, "t1")
	if res.Workflow != "" || !strings.Contains(logged, "Fix DEV-1") || !strings.Contains(logged, "there is no earlier good version, so the host's settings hold alone") {
		t.Errorf("workflow %q, log:\n%s", res.Workflow, logged)
	}
}

func hookList(name string) string {
	var quoted []string
	for _, a := range helper("mark", name) {
		quoted = append(quoted, fmt.Sprintf("%q", a))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// A repository narrows the tier and adds hooks, when the host allows hooks.
// What would widen the tier is ignored and reported; the rest holds.
func TestWorkflowNarrowsAndDoesNotWiden(t *testing.T) {
	hooks := "hooks:\n  after_create: " + hookList("repo_after_create") + "\n  before_run: " + hookList("repo_before_run") + "\n  after_run: " + hookList("repo_after_run") + "\n"
	host := config.Workspace{Hooks: config.Hooks{BeforeRun: helper("mark", "before_run")}}
	pol := func(gate string) func(*Runner) {
		return func(r *Runner) {
			p := policy.Builtin()
			p.Tiers[0].PlanGate = gate
			if err := r.UsePolicy(p); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Narrower: a plan gate that the tier does not have, and hooks that the
	// host allows. They run after the host's.
	src := &fakeSource{}
	src.set("v1", "---\nplan_gate: required\n"+hooks+"---\nRules."+promptTail)
	w := newWorkspaceRunner(t, host, pol(policy.PlanGateSkip), func(r *Runner) { r.UseWorkflow(config.Workflow{Enabled: true, AllowHooks: true}, src) })
	res, logged := w.runRepo(t, "t1")
	if res.Phase != task.PhasePlan || !strings.Contains(logged, "This run is for the plan only.") {
		t.Errorf("the repository's plan gate did not hold: phase %q, log:\n%s", res.Phase, logged)
	}
	want := []string{
		"repo_after_create in DEV-1 branch=bot/DEV-1 hook=after_create",
		"before_run in DEV-1 branch=bot/DEV-1 hook=before_run",
		"repo_before_run in DEV-1 branch=bot/DEV-1 hook=before_run",
		"agent in DEV-1 branch=bot/DEV-1 hook=",
		"repo_after_run in DEV-1 branch=bot/DEV-1 hook=after_run",
	}
	if got := w.ran(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ran:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(logged, "# ---- hook before_run of WORKFLOW.md: ") {
		t.Errorf("the run log does not name the repository's hook:\n%s", logged)
	}
	if st, _ := w.Status(); len(st.Workflows) != 1 || len(st.Workflows[0].Ignored) != 0 {
		t.Errorf("status: %+v", st.Workflows)
	}

	// Wider: no plan where the tier requires one, and hooks that the host
	// does not allow. Both are ignored; the prompt of the same file holds.
	src = &fakeSource{}
	src.set("v1", "---\nplan_gate: skip\n"+hooks+"---\nRules."+promptTail)
	w = newWorkspaceRunner(t, host, pol(policy.PlanGateRequired), func(r *Runner) { r.UseWorkflow(config.Workflow{Enabled: true}, src) })
	res, logged = w.runRepo(t, "t1")
	if res.Phase != task.PhasePlan || res.Workflow != "v1" || !strings.Contains(logged, "Rules.") {
		t.Errorf("the tier's plan gate did not hold: phase %q, workflow %q, log:\n%s", res.Phase, res.Workflow, logged)
	}
	want = []string{"before_run in DEV-1 branch=bot/DEV-1 hook=before_run", "agent in DEV-1 branch=bot/DEV-1 hook="}
	if got := w.ran(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ran:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	st, _ := w.Status()
	if len(st.Workflows) != 1 || len(st.Workflows[0].Ignored) != 4 || !strings.Contains(st.Workflows[0].Ignored[0], "plan_gate: skip is ignored: the tier normal requires an approved plan") ||
		!strings.Contains(st.Workflows[0].Ignored[1], "hooks.after_create is ignored") {
		t.Errorf("status: %+v", st.Workflows)
	}
	for _, line := range st.Workflows[0].Ignored {
		if !strings.Contains(logged, "# workflow: "+line) {
			t.Errorf("the run log lacks %q:\n%s", line, logged)
		}
	}
}

// The status of the hand-over: the repository's choice, when the host
// lists it.
func TestWorkflowReviewStatus(t *testing.T) {
	src := &fakeSource{}
	src.set("v1", "---\nreview_status: code review\n---\n")
	w := newWorkspaceRunner(t, config.Workspace{}, func(r *Runner) {
		r.UseWorkflow(config.Workflow{Enabled: true, ReviewStatuses: []string{"In Review", "Code Review"}}, src)
	})
	if got := w.ReviewStatus("jira", "DEV-1"); got != "" {
		t.Errorf("before any run: %q", got)
	}
	w.runRepo(t, "t1")
	if got := w.ReviewStatus("jira", "DEV-1"); got != "Code Review" {
		t.Errorf("a listed status: %q", got)
	}
	src.set("v2", "---\nreview_status: Done\n---\n")
	_, logged := w.runRepo(t, "t2")
	if got := w.ReviewStatus("jira", "DEV-1"); got != "" || !strings.Contains(logged, `# workflow: review_status: "Done" is ignored`) {
		t.Errorf("a status that is not listed: %q, log:\n%s", got, logged)
	}
}
