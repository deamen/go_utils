//go:build unix

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ochell/internal/config"
)

func TestMain(m *testing.M) {
	code := m.Run()
	RemoveBinaries()
	os.Exit(code)
}

// A Linear ticket runs from the webhook to the result posted on the session.
func TestLinearTicketFromWebhookToResult(t *testing.T) {
	o := Start(t, Options{})
	id := o.LinearCreated("ENG-123", "session-1", `<issue identifier="ENG-123"><title>Add retry</title></issue>`).TaskID(t)

	run := o.WaitRun(id, 15*time.Second)
	if run.ExitCode != 0 {
		t.Fatalf("exit code %d: %s", run.ExitCode, run.Footer)
	}
	if !strings.Contains(run.Log, "fake agent finished ENG-123") {
		t.Errorf("agent output missing from the log:\n%s", run.Log)
	}

	recs := o.WaitRecords(1, 5*time.Second)
	if len(recs) != 1 {
		t.Fatalf("agent started %d times, want 1", len(recs))
	}
	rec := recs[0]
	for _, want := range []string{"linear ticket ENG-123", "https://linear.app/example/issue/ENG-123", "<title>Add retry</title>"} {
		if !strings.Contains(rec.Stdin, want) {
			t.Errorf("prompt on stdin missing %q:\n%s", want, rec.Stdin)
		}
	}
	if len(rec.Args) != 0 {
		t.Errorf("agent arguments = %q, want none", rec.Args)
	}
	for name, want := range map[string]string{"ORCH_TASK_ID": id, "ORCH_TASK_SOURCE": "linear", "ORCH_TASK_KEY": "ENG-123"} {
		if got, _ := rec.Getenv(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if want := filepath.Join(o.Dir, "work", "linear-ENG-123"); rec.Dir != want {
		t.Errorf("working directory = %q, want %q", rec.Dir, want)
	}

	acts := o.WaitActivities("session-1", 2, 10*time.Second)
	if acts[0].Type != "thought" || !strings.Contains(acts[0].Body, "ENG-123") {
		t.Errorf("first activity = %+v, want the acknowledgement", acts[0])
	}
	if acts[1].Type != "response" || !strings.Contains(acts[1].Body, "fake agent finished ENG-123") {
		t.Errorf("second activity = %+v, want the agent result", acts[1])
	}
}

func TestJiraTicketsFromWebhookToResult(t *testing.T) {
	o := Start(t, Options{})
	hook := o.JiraAssigned("DEV-42", "Add retry to the payment client").TaskID(t)
	auto := o.JiraAutomation("DEV-43", "Fix the login page").TaskID(t)
	for id, key := range map[string]string{hook: "DEV-42", auto: "DEV-43"} {
		run := o.WaitRun(id, 15*time.Second)
		if run.ExitCode != 0 || !strings.Contains(run.Log, "fake agent finished "+key) {
			t.Errorf("%s: exit %d, log:\n%s", key, run.ExitCode, run.Log)
		}
	}
	if recs := o.WaitRecords(2, 5*time.Second); len(recs) != 2 {
		t.Errorf("agent started %d times, want 2", len(recs))
	}
}

func TestFailingAgentIsReported(t *testing.T) {
	o := Start(t, Options{Script: []Step{{Print: "working"}, {Eprint: "cannot push the branch"}, Exit(3)}})
	id := o.LinearCreated("ENG-7", "session-fail", "").TaskID(t)
	if run := o.WaitRun(id, 15*time.Second); run.ExitCode != 3 {
		t.Fatalf("exit code %d, want 3: %s", run.ExitCode, run.Footer)
	}
	acts := o.WaitActivities("session-fail", 2, 10*time.Second)
	if acts[1].Type != "error" || !strings.Contains(acts[1].Body, "cannot push the branch") {
		t.Errorf("second activity = %+v, want an error with the agent output", acts[1])
	}
}

// The agent must not see the secrets that ochell holds in its environment.
func TestAgentDoesNotSeeOchellSecrets(t *testing.T) {
	secrets := []string{
		"JIRA_WEBHOOK_SECRET=jira-env-secret",
		"LINEAR_CLIENT_SECRET=linear-env-secret",
		"NGROK_API_KEY=ngrok-env-secret",
	}
	o := Start(t, Options{Env: secrets})
	id := o.JiraAssigned("DEV-1", "Print the environment").TaskID(t)
	o.WaitRun(id, 15*time.Second)
	rec := o.WaitRecords(1, 5*time.Second)[0]
	env := strings.Join(rec.Env, "\n")
	for _, s := range secrets {
		name, value, _ := strings.Cut(s, "=")
		if strings.Contains(env, name) || strings.Contains(env, value) {
			t.Errorf("agent environment contains %s", name)
		}
	}
	for _, s := range []string{JiraSecret, AutomationToken, LinearSecret, LinearToken} {
		if strings.Contains(env, s) {
			t.Errorf("agent environment contains a configured secret (%s)", s)
		}
	}
	if _, ok := rec.Getenv("PATH"); !ok {
		t.Error("agent environment has no PATH")
	}
}

// A prompt far above the 128 KB limit for one argument reaches the agent,
// and is not on its command line, where the process list would show it.
func TestLargePromptOnStdin(t *testing.T) {
	o := Start(t, Options{Configure: func(c *config.Config) {
		// The shipped defaults, not the harness's own choice.
		c.Agent.PromptVia = config.Default().Agent.PromptVia
		c.Agent.Args = config.Default().Agent.Args
	}})
	const marker = "MARKER-IN-TICKET-TEXT"
	context := marker + strings.Repeat(" 0123456789abcdef", 500*1024/17) + marker
	if len(context) < 500*1024 {
		t.Fatalf("test context is only %d bytes", len(context))
	}
	id := o.LinearCreated("ENG-500", "session-large", context).TaskID(t)
	if run := o.WaitRun(id, 20*time.Second); run.ExitCode != 0 {
		t.Fatalf("exit code %d: %s", run.ExitCode, run.Footer)
	}
	rec := o.WaitRecords(1, 5*time.Second)[0]
	if !strings.Contains(rec.Stdin, context) {
		t.Errorf("the agent received %d bytes on stdin, without the full %d byte context", len(rec.Stdin), len(context))
	}
	// The arguments are what the process list shows.
	if got := strings.Join(rec.Args, " "); got != "-p" || strings.Contains(got, marker) {
		t.Errorf("agent arguments = %.200q, want only -p", got)
	}
}
