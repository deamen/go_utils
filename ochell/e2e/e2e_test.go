//go:build unix

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ochell/internal/config"
	"ochell/internal/store"
	"ochell/internal/tracker/jiraapi/jiratest"
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

// The systemd launcher and the real launch and stop scripts, with systemd
// itself replaced by stand-ins. What only real systemd can show (another OS
// user, the unit's cgroup) is in TestSystemdLauncherOnVM.
func TestSystemdLauncherThroughScripts(t *testing.T) {
	var root string
	o := Start(t, Options{
		Env: []string{"JIRA_WEBHOOK_SECRET=jira-env-secret"},
		Configure: func(c *config.Config) {
			root = UseFakeSystemd(t, c)
			c.Agent.Args = []string{"--session", "{{.Source}}-{{.Key}}"}
		},
	})
	// Ticket text that would make systemd put the token on the command line
	// if it ever reached an argument.
	id := o.LinearCreated("ENG-9", "session-systemd", "context with ${AGENT_TOKEN} and $$").TaskID(t)
	run := o.WaitRun(id, 15*time.Second)
	if run.ExitCode != 0 || !strings.Contains(run.Footer, "outcome=finished") {
		t.Fatalf("run: %s\n%s", run.Footer, run.Log)
	}
	rec := o.WaitRecords(1, 5*time.Second)[0]
	if !strings.Contains(rec.Stdin, "context with ${AGENT_TOKEN} and $$") {
		t.Errorf("prompt on stdin was changed:\n%s", rec.Stdin)
	}
	if got := strings.Join(rec.Args, " "); got != "--session linear-ENG-9" {
		t.Errorf("agent arguments = %q", got)
	}
	if want := filepath.Join(root, "linear-ENG-9"); rec.Dir != want {
		t.Errorf("working directory = %q, want %q", rec.Dir, want)
	}
	// The unit has its own environment: the token from the root-only file
	// and what ochell sets, but nothing inherited from ochell.
	if got, _ := rec.Getenv("AGENT_TOKEN"); got != AgentToken {
		t.Errorf("AGENT_TOKEN = %q, want the value from the environment file", got)
	}
	if got, _ := rec.Getenv("ORCH_TASK_KEY"); got != "ENG-9" {
		t.Errorf("ORCH_TASK_KEY = %q", got)
	}
	for _, name := range []string{"JIRA_WEBHOOK_SECRET", "HOME", "OCHELL_LAUNCHER_CONF"} {
		if v, ok := rec.Getenv(name); ok {
			t.Errorf("the unit inherited %s=%q from ochell", name, v)
		}
	}
	if acts := o.WaitActivities("session-systemd", 2, 10*time.Second); acts[1].Type != "response" {
		t.Errorf("second activity = %+v, want the agent result", acts[1])
	}
}

func TestSystemdLauncherStopsAtTimeLimit(t *testing.T) {
	o := Start(t, Options{
		Script: []Step{{Print: "working"}, {Sleep: "10m"}},
		Configure: func(c *config.Config) {
			UseFakeSystemd(t, c)
			c.Agent.Timeout = time.Second
			c.Agent.StopGrace = 2 * time.Second
		},
	})
	id := o.LinearCreated("ENG-10", "session-timeout", "").TaskID(t)
	run := o.WaitRun(id, 20*time.Second)
	if !strings.Contains(run.Footer, "outcome=timed_out") {
		t.Fatalf("run: %s", run.Footer)
	}
	rec := o.WaitRecords(1, 5*time.Second)[0]
	if Alive(rec.PID) {
		t.Errorf("the agent (pid %d) is still running after the time limit", rec.PID)
	}
	acts := o.WaitActivities("session-timeout", 2, 10*time.Second)
	if acts[1].Type != "error" || !strings.Contains(acts[1].Body, "timed out") {
		t.Errorf("second activity = %+v, want an error that names the time limit", acts[1])
	}
}

// A launch that the script refuses is reported as "not started", with the
// script's reason, not as an agent failure.
func TestSystemdLauncherRefusedLaunch(t *testing.T) {
	o := Start(t, Options{Configure: func(c *config.Config) {
		UseFakeSystemd(t, c)
		c.Agent.Workdir = "/outside-the-workspace/{{.Key}}"
	}})
	id := o.LinearCreated("ENG-11", "session-refused", "").TaskID(t)
	run := o.WaitRun(id, 15*time.Second)
	if run.ExitCode != 250 || !strings.Contains(run.Footer, "outcome=not_started") {
		t.Errorf("run: %s", run.Footer)
	}
	if !strings.Contains(run.Log, "ochell-launch: the working directory is outside") {
		t.Errorf("the log does not hold the reason:\n%s", run.Log)
	}
	if len(o.Records()) != 0 {
		t.Error("the agent ran although the launch was refused")
	}
	acts := o.WaitActivities("session-refused", 2, 10*time.Second)
	if acts[1].Type != "error" || !strings.Contains(acts[1].Body, "did not start") {
		t.Errorf("second activity = %+v", acts[1])
	}
}

// A second Linear session on a ticket that is running starts no second run,
// and is answered within the 10 seconds Linear allows.
func TestSecondLinearSessionOnRunningTicket(t *testing.T) {
	o := Start(t, Options{Script: []Step{{Print: "working"}, {Sleep: "3s"}, {Print: "all done"}, Report("done", "all done")}})
	id := o.LinearCreated("ENG-78", "session-first", "").TaskID(t)
	o.WaitRecords(1, 10*time.Second)

	sent := time.Now()
	second := o.LinearCreated("ENG-78", "session-second", "")
	if second.Status != 200 || second.Body != "already in progress" {
		t.Fatalf("second trigger: %d %q", second.Status, second.Body)
	}
	acts := o.WaitActivities("session-second", 1, 10*time.Second)
	if d := acts[0].At.Sub(sent); d > 10*time.Second {
		t.Errorf("the second session was answered after %s", d)
	}
	if acts[0].Type != "response" || !strings.Contains(acts[0].Body, "ENG-78 is already being worked on") {
		t.Errorf("activity on the second session = %+v", acts[0])
	}

	if run := o.WaitRun(id, 20*time.Second); run.ExitCode != 0 {
		t.Errorf("first run: %s", run.Footer)
	}
	if n := len(o.Records()); n != 1 {
		t.Errorf("the agent was started %d times, want 1", n)
	}
	// The first session gets its acknowledgement and the result; the second
	// nothing more.
	if first := o.WaitActivities("session-first", 2, 10*time.Second); first[1].Type != "response" || !strings.Contains(first[1].Body, "all done") {
		t.Errorf("first session = %+v", first)
	}
	if n := len(o.Linear.Activities("session-second")); n != 1 {
		t.Errorf("the second session got %d activities, want 1", n)
	}
}

// spawning is a fake agent that behaves like a real one with sub-agents and
// MCP servers: it starts children and keeps working.
func spawning(children ...Step) []Step {
	return append(children, Step{Print: "working"}, Step{Sleep: "10m"})
}

func expectAllGone(t *testing.T, rec Record, wantChildren int) {
	t.Helper()
	if len(rec.Children) != wantChildren {
		t.Fatalf("the agent started %d children, want %d", len(rec.Children), wantChildren)
	}
	// The processes are killed, not waited for; give the kernel a moment.
	deadline := time.Now().Add(5 * time.Second)
	for _, pid := range append([]int{rec.PID}, rec.Children...) {
		for Alive(pid) {
			if time.Now().After(deadline) {
				t.Errorf("process %d is still running", pid)
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// waitChildren waits until the fake agent has recorded its children.
func waitChildren(t *testing.T, o *Ochell, n int) Record {
	t.Helper()
	var rec Record
	o.waitFor(10*time.Second, "the agent to start its children", func() bool {
		recs := o.Records()
		if len(recs) == 0 || len(recs[0].Children) < n {
			return false
		}
		rec = recs[0]
		return true
	})
	return rec
}

// At the time limit the whole agent is stopped, not only its top process.
func TestTimeoutLeavesNoProcessBehind(t *testing.T) {
	o := Start(t, Options{
		// One child ignores SIGTERM, and so does the agent itself.
		Script: append([]Step{{IgnoreTerm: true}}, spawning(Step{Spawn: &Spawn{Count: 2}}, Step{Spawn: &Spawn{Count: 1, IgnoreTerm: true}})...),
		Configure: func(c *config.Config) {
			c.Agent.Timeout = time.Second
			c.Agent.StopGrace = time.Second
		},
	})
	id := o.JiraAssigned("DEV-7", "Spawn children").TaskID(t)
	rec := waitChildren(t, o, 3)
	run := o.WaitRun(id, 20*time.Second)
	if !strings.Contains(run.Footer, "outcome=timed_out") {
		t.Errorf("run: %s", run.Footer)
	}
	expectAllGone(t, rec, 3)
}

// A shutdown waits for running agents up to drain_timeout, then stops them
// with all their children.
func TestShutdownLeavesNoProcessBehind(t *testing.T) {
	o := Start(t, Options{
		Script: spawning(Step{Spawn: &Spawn{Count: 2}}, Step{Spawn: &Spawn{Count: 1, IgnoreTerm: true}}),
		Configure: func(c *config.Config) {
			c.Agent.DrainTimeout = time.Second
			c.Agent.StopGrace = time.Second
		},
	})
	id := o.LinearCreated("ENG-27", "session-shutdown", "").TaskID(t)
	rec := waitChildren(t, o, 3)
	sent := time.Now()
	o.Signal(syscall.SIGTERM)
	if code := o.WaitExit(20 * time.Second); code != 0 {
		t.Errorf("ochell exit code %d", code)
	}
	if d := time.Since(sent); d < time.Second {
		t.Errorf("ochell exited after %s, before drain_timeout was over", d)
	}
	run := o.WaitRun(id, time.Second)
	if !strings.Contains(run.Footer, "outcome=stopped") {
		t.Errorf("run: %s", run.Footer)
	}
	expectAllGone(t, rec, 3)
	// The ticket is told that the run was cut short and goes on later.
	acts := o.Linear.Activities("session-shutdown")
	if len(acts) != 2 || acts[1].Type != "thought" || !strings.Contains(acts[1].Body, "queued again") {
		t.Errorf("activities = %+v, want a thought that says the run is queued again", acts)
	}
}

// An agent that finishes within drain_timeout is not cut short by a
// shutdown, and no new webhook is accepted meanwhile.
func TestShutdownWaitsForRunningAgent(t *testing.T) {
	o := Start(t, Options{
		Script:    []Step{{Print: "started"}, {Sleep: "1500ms"}, {Print: "all done"}, Report("done", "all done")},
		Configure: func(c *config.Config) { c.Agent.DrainTimeout = 30 * time.Second },
	})
	id := o.LinearCreated("ENG-28", "session-drain", "").TaskID(t)
	o.WaitRecords(1, 10*time.Second)
	o.Signal(syscall.SIGTERM)
	if code := o.WaitExit(20 * time.Second); code != 0 {
		t.Errorf("ochell exit code %d", code)
	}
	run := o.WaitRun(id, time.Second)
	if !strings.Contains(run.Footer, "outcome=finished") || !strings.Contains(run.Log, "all done") {
		t.Errorf("the run was cut short: %s\n%s", run.Footer, run.Log)
	}
	if acts := o.Linear.Activities("session-drain"); len(acts) != 2 || acts[1].Type != "response" {
		t.Errorf("activities = %+v, want the agent result", acts)
	}
}

// A second signal ends the wait.
func TestSecondSignalStopsAgentsNow(t *testing.T) {
	o := Start(t, Options{
		Script: spawning(Step{Spawn: &Spawn{Count: 1}}),
		Configure: func(c *config.Config) {
			c.Agent.DrainTimeout = 10 * time.Minute
			c.Agent.StopGrace = time.Second
		},
	})
	id := o.JiraAssigned("DEV-8", "Long run").TaskID(t)
	rec := waitChildren(t, o, 1)
	o.Signal(syscall.SIGTERM)
	o.waitFor(10*time.Second, "ochell to start waiting for the agent", func() bool {
		return strings.Contains(o.Output(), "waiting for running agents")
	})
	o.Signal(syscall.SIGTERM)
	if code := o.WaitExit(20 * time.Second); code != 0 {
		t.Errorf("ochell exit code %d", code)
	}
	if run := o.WaitRun(id, time.Second); !strings.Contains(run.Footer, "outcome=stopped") {
		t.Errorf("run: %s", run.Footer)
	}
	expectAllGone(t, rec, 1)
}

// The agent signal contract: the agent says how its run ended in a result
// file, and that decides what the ticket is told and which state it is in.
func TestAgentSignal(t *testing.T) {
	// ticket returns the stored ticket once the end of run id is stored.
	ticket := func(t *testing.T, o *Ochell, key, id string) *store.Ticket {
		t.Helper()
		st, err := store.Open(o.Config.Store.Path)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		o.WaitStored(st, id, 15*time.Second)
		tk, err := st.Ticket("linear", key)
		if err != nil || tk == nil {
			t.Fatalf("stored ticket %s: %v, %v", key, tk, err)
		}
		return tk
	}

	t.Run("a question", func(t *testing.T) {
		o := Start(t, Options{Script: []Step{{Print: "I looked at the ticket."}, Report("needs_input", "Which of the two login pages do you mean?")}})
		id := o.LinearCreated("ENG-41", "session-question", "").TaskID(t)
		if run := o.WaitRun(id, 15*time.Second); !strings.Contains(run.Footer, "outcome=finished result=needs_input") {
			t.Errorf("run: %s", run.Footer)
		}
		// The question is asked on the ticket, and the session waits for a reply.
		acts := o.WaitActivities("session-question", 2, 10*time.Second)
		if acts[1].Type != "elicitation" || acts[1].Body != "Which of the two login pages do you mean?" {
			t.Errorf("the ticket got %+v, want the question as an elicitation", acts[1])
		}
		if tk := ticket(t, o, "ENG-41", id); tk.State != "waiting" || tk.Reason != "input" {
			t.Errorf("ticket is %s (%s), want waiting (input)", tk.State, tk.Reason)
		}

		// What the agent was given: the instructions in the prompt, and a
		// path outside its working directory.
		rec := o.WaitRecords(1, 5*time.Second)[0]
		if !strings.Contains(rec.Stdin, "ORCH_RESULT_FILE") || !strings.Contains(rec.Stdin, "needs_input") {
			t.Errorf("the prompt does not tell the agent to write the result file:\n%s", rec.Stdin)
		}
		file, _ := rec.Getenv("ORCH_RESULT_FILE")
		if !filepath.IsAbs(file) || strings.HasPrefix(file, rec.Dir+string(filepath.Separator)) {
			t.Errorf("ORCH_RESULT_FILE = %q, want an absolute path outside the working directory %q", file, rec.Dir)
		}
		if got := rec.Writes["$ORCH_RESULT_FILE"]; got != "ok" {
			t.Errorf("the agent could not write its result file: %s", got)
		}
	})

	t.Run("no result file", func(t *testing.T) {
		o := Start(t, Options{Script: []Step{{Print: "I think I am done."}}})
		id := o.LinearCreated("ENG-42", "session-silent", "").TaskID(t)
		if run := o.WaitRun(id, 15*time.Second); !strings.Contains(run.Footer, "outcome=finished result=none") {
			t.Errorf("run: %s", run.Footer)
		}
		acts := o.WaitActivities("session-silent", 2, 10*time.Second)
		if acts[1].Type != "elicitation" || !strings.Contains(acts[1].Body, "I think I am done.") || !strings.Contains(acts[1].Body, "without reporting a result") {
			t.Errorf("the ticket got %+v", acts[1])
		}
		if tk := ticket(t, o, "ENG-42", id); tk.State != "waiting" || tk.Reason != "no_result" {
			t.Errorf("ticket is %s (%s), want waiting (no_result)", tk.State, tk.Reason)
		}
	})

	t.Run("an invalid result file", func(t *testing.T) {
		o := Start(t, Options{Script: []Step{{WriteFile: &File{Path: "$ORCH_RESULT_FILE", Content: `{"status":"all good"}`}}}})
		id := o.LinearCreated("ENG-43", "session-invalid", "").TaskID(t)
		if run := o.WaitRun(id, 15*time.Second); !strings.Contains(run.Footer, "result=invalid") {
			t.Errorf("run: %s", run.Footer)
		}
		if tk := ticket(t, o, "ENG-43", id); tk.State != "waiting" || tk.Reason != "no_result" {
			t.Errorf("ticket is %s (%s), want waiting (no_result)", tk.State, tk.Reason)
		}
	})

	t.Run("done with a pull request", func(t *testing.T) {
		o := Start(t, Options{Script: []Step{Report("done", "Opened a pull request.", "pr_url", "https://github.com/example/repo/pull/7", "branch", "bot/ENG-44")}})
		id := o.LinearCreated("ENG-44", "session-done", "").TaskID(t)
		o.WaitRun(id, 15*time.Second)
		acts := o.WaitActivities("session-done", 2, 10*time.Second)
		if acts[1].Type != "response" || acts[1].Body != "Opened a pull request." {
			t.Errorf("the ticket got %+v", acts[1])
		}
		tk := ticket(t, o, "ENG-44", id)
		if tk.State != "in_review" || tk.PRURL != "https://github.com/example/repo/pull/7" || tk.Branch != "bot/ENG-44" {
			t.Errorf("ticket = %+v, want in_review with the pull request and the branch", tk)
		}
	})

	t.Run("a failed run is not believed", func(t *testing.T) {
		o := Start(t, Options{Script: []Step{Report("done", "All fine."), Exit(3)}})
		id := o.LinearCreated("ENG-45", "session-failed", "").TaskID(t)
		o.WaitRun(id, 15*time.Second)
		if acts := o.WaitActivities("session-failed", 2, 10*time.Second); acts[1].Type != "error" {
			t.Errorf("the ticket got %+v, want an error", acts[1])
		}
		if tk := ticket(t, o, "ENG-45", id); tk.State != "failed" {
			t.Errorf("ticket is %s, want failed", tk.State)
		}
	})
}

// The attempt cap: a ticket stops after max_attempts runs, until someone
// resets it.
func TestAttemptCap(t *testing.T) {
	o := Start(t, Options{Configure: func(c *config.Config) { c.Agent.MaxAttempts = 2 }})
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i, session := range []string{"session-1", "session-2"} {
		id := o.LinearCreated("ENG-45", session, "").TaskID(t)
		if run := o.WaitStored(st, id, 15*time.Second); run.Attempt != i+1 {
			t.Fatalf("run %d was attempt %d", i+1, run.Attempt)
		}
		o.WaitActivities(session, 2, 10*time.Second)
	}

	// The third assignment starts nothing.
	third := o.LinearCreated("ENG-45", "session-3", "")
	if third.Status != 200 || third.Body != "not started: ENG-45 has used its 2 attempts" {
		t.Fatalf("third assignment: %d %q", third.Status, third.Body)
	}
	acts := o.WaitActivities("session-3", 1, 10*time.Second)
	if acts[0].Type != "elicitation" || !strings.Contains(acts[0].Body, "has used its 2 attempts") || !strings.Contains(acts[0].Body, "ochell reset linear ENG-45") {
		t.Errorf("the session got %+v", acts[0])
	}
	if tk, _ := st.Ticket("linear", "ENG-45"); tk.State != "waiting" || tk.Reason != "escalation" || tk.Attempts != 2 {
		t.Errorf("ticket = %s (%s) with %d attempts, want waiting (escalation) with 2", tk.State, tk.Reason, tk.Attempts)
	}
	if n := len(o.Records()); n != 2 {
		t.Errorf("the agent was started %d times, want 2", n)
	}
	if !strings.Contains(o.Output(), "ticket not started: it has used up its attempts") {
		t.Error("the refusal is not in ochell's log")
	}

	// An operator looks at it and resets it; then it can be assigned again.
	if out, code := o.Admin("reset", "linear", "ENG-45"); code != 0 || !strings.Contains(out, "attempts of linear ENG-45 are reset") {
		t.Fatalf("ochell reset: exit %d, %q", code, out)
	}
	if out, code := o.Admin("reset", "linear", "ENG-404"); code == 0 || !strings.Contains(out, "knows no linear ticket ENG-404") {
		t.Errorf("ochell reset of an unknown ticket: exit %d, %q", code, out)
	}
	id := o.LinearCreated("ENG-45", "session-4", "").TaskID(t)
	if run := o.WaitStored(st, id, 15*time.Second); run.Attempt != 1 {
		t.Errorf("the run after the reset was attempt %d, want 1", run.Attempt)
	}
}

// The pause flag: ochell pause and ochell resume take effect on the running
// server, and no run starts while it is paused.
func TestPauseAndResume(t *testing.T) {
	o := Start(t, Options{})
	if out, code := o.Admin("status"); code != 0 || out != "running; 0 queued, 0 running" {
		t.Fatalf("ochell status: exit %d, %q", code, out)
	}
	if out, code := o.Admin("pause"); code != 0 || out != "paused: no new run starts; 0 queued, 0 running" {
		t.Fatalf("ochell pause: exit %d, %q", code, out)
	}

	// Webhooks are still accepted, and queued.
	id := o.JiraAssigned("DEV-45", "Arrives during the pause").TaskID(t)
	time.Sleep(500 * time.Millisecond)
	if n := len(o.Records()); n != 0 {
		t.Fatalf("a run started while ochell was paused (%d)", n)
	}
	if _, err := os.Stat(o.LogFile(id)); err == nil {
		t.Error("the queued task has a run log while ochell is paused")
	}
	if out, _ := o.Admin("status"); out != "paused: no new run starts; 1 queued, 0 running" {
		t.Errorf("ochell status during the pause: %q", out)
	}

	// The pause is kept across a restart.
	o.Signal(syscall.SIGTERM)
	o.WaitExit(20 * time.Second)
	o.Restart()
	time.Sleep(300 * time.Millisecond)
	if out, _ := o.Admin("status"); out != "paused: no new run starts; 1 queued, 0 running" || len(o.Records()) != 0 {
		t.Errorf("after a restart: %q, %d runs; want still paused with the task queued", out, len(o.Records()))
	}

	// Resume, without a restart: the queued task runs.
	if out, code := o.Admin("resume"); code != 0 || !strings.HasPrefix(out, "running; ") {
		t.Fatalf("ochell resume: exit %d, %q", code, out)
	}
	if run := o.WaitRun(id, 15*time.Second); !strings.Contains(run.Footer, "outcome=finished") {
		t.Errorf("the queued task after the resume: %s", run.Footer)
	}
}

// The assigner allowlist: an assignment from someone who is not on it is
// rejected and logged, for each source.
func TestAssignerAllowlist(t *testing.T) {
	o := Start(t, Options{Configure: func(c *config.Config) {
		c.Sources.JiraWebhook.AllowedAssigners = []string{HumanAccountID}
		c.Sources.JiraAutomation.AllowedAssigners = []string{HumanAccountID}
		c.Sources.Linear.AllowedAssigners = []string{"Human@Example.com"}
	}})

	// Someone on the list.
	o.WaitRun(o.JiraAssigned("DEV-50", "Allowed").TaskID(t), 15*time.Second)
	o.WaitRun(o.JiraAutomation("DEV-51", "Allowed").TaskID(t), 15*time.Second)
	o.WaitRun(o.LinearCreated("ENG-50", "session-allowed", "").TaskID(t), 15*time.Second)
	runs := len(o.Records())

	// Someone else.
	o.Actor = "557058:stranger"
	if r := o.JiraAssigned("DEV-52", "Not allowed"); r.Status != 403 || r.Body != "the assigner is not allowed to assign work" {
		t.Errorf("Jira webhook from a stranger: %d %q", r.Status, r.Body)
	}
	if r := o.JiraAutomation("DEV-53", "Not allowed"); r.Status != 403 {
		t.Errorf("Jira Automation from a stranger: %d %q", r.Status, r.Body)
	}
	if !strings.Contains(o.Output(), `msg="rejected: the assigner is not on the allowlist" source=jira_webhook`) ||
		!strings.Contains(o.Output(), "key=DEV-52 assigner=557058:stranger") {
		t.Error("the rejected Jira assignment is not in ochell's log")
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(o.Records()); n != runs {
		t.Errorf("a run started for a rejected assignment: %d runs, want %d", n, runs)
	}
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if tk, _ := st.Ticket("jira", "DEV-52"); tk != nil {
		t.Errorf("a rejected assignment left a ticket behind: %+v", tk)
	}
}

// git runs git with a fixed identity, and fails the test when it fails.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=e2e", "-c", "user.email=e2e@example.com", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// The workspace hooks: a new ticket gets a clone of its repository on the
// branch bot/<KEY>, a second run reuses it, and the working directory of a
// closed ticket is removed.
func TestWorkspaceLifecycle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	// A repository to clone, with one commit.
	origin := filepath.Join(t.TempDir(), "backend.git")
	seed := t.TempDir()
	git(t, seed, "init", "-q")
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("backend\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, seed, "add", "README.md")
	git(t, seed, "commit", "-q", "-m", "first commit")
	git(t, seed, "clone", "-q", "--bare", seed, origin)

	o := Start(t, Options{
		// The agent leaves a file behind, as work in progress.
		Script: []Step{{WriteFile: &File{Path: "notes.txt", Content: "work in progress"}}, Report("done", "Pushed a branch.")},
		Configure: func(c *config.Config) {
			c.Repos = []config.Repo{{Source: "jira", Project: "DEV", Repo: origin}}
			c.Workspace.Root = filepath.Dir(c.Agent.Workdir)
			c.Workspace.Cleanup = true
			c.Workspace.Hooks.AfterCreate = []string{"/bin/sh", "-c", `git clone -q "$ORCH_TASK_REPO" . && git checkout -q -b "$ORCH_TASK_BRANCH"`}
			c.Workspace.Hooks.BeforeRun = []string{"/bin/sh", "-c", `git fetch -q origin && echo "fetched on $(git rev-parse --abbrev-ref HEAD)"`}
		},
	})
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A new ticket: its working directory is a clone on the branch bot/DEV-44.
	first := o.JiraAssigned("DEV-44", "Needs a workspace").TaskID(t)
	run := o.WaitRun(first, 30*time.Second)
	if !strings.Contains(run.Footer, "outcome=finished") {
		t.Fatalf("first run: %s\n%s", run.Footer, run.Log)
	}
	dir := o.WaitStored(st, first, 10*time.Second).Result.Workdir
	if got := git(t, dir, "rev-parse", "--abbrev-ref", "HEAD"); got != "bot/DEV-44" {
		t.Errorf("branch of the working directory = %q, want bot/DEV-44", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Errorf("the working directory is not a clone of the repository: %v", err)
	}
	if !strings.Contains(run.Log, "# ---- hook after_create: ") || !strings.Contains(run.Log, "fetched on bot/DEV-44") {
		t.Errorf("the first run's log does not show the hooks:\n%s", run.Log)
	}
	rec := o.WaitRecords(1, 5*time.Second)[0]
	if got, _ := rec.Getenv("ORCH_TASK_BRANCH"); got != "bot/DEV-44" || rec.Dir != dir {
		t.Errorf("the agent ran in %q with ORCH_TASK_BRANCH=%q", rec.Dir, got)
	}

	// A second run reuses it: no second clone, and the first run's file is there.
	second := o.JiraAssigned("DEV-44", "Needs a workspace").TaskID(t)
	run = o.WaitRun(second, 30*time.Second)
	o.WaitStored(st, second, 10*time.Second)
	if !strings.Contains(run.Footer, "outcome=finished") || strings.Contains(run.Log, "hook after_create") || !strings.Contains(run.Log, "fetched on bot/DEV-44") {
		t.Errorf("second run: %s\n%s", run.Footer, run.Log)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Errorf("the second run did not get the first run's working directory: %v", err)
	}

	// The ticket is closed in Jira: the working directory goes.
	if r := o.JiraResolved("DEV-44"); r.Status != 200 || r.Body != "closed DEV-44" {
		t.Fatalf("resolved ticket: %d %q", r.Status, r.Body)
	}
	o.waitFor(15*time.Second, "the working directory to be removed", func() bool {
		_, err := os.Stat(dir)
		return os.IsNotExist(err)
	})
	o.waitFor(5*time.Second, "the removal to be recorded", func() bool {
		tk, _ := st.Ticket("jira", "DEV-44")
		return tk != nil && tk.Workspace == ""
	})
	if tk, _ := st.Ticket("jira", "DEV-44"); tk.State != "done" || tk.PreparedWorkspace != "" {
		t.Errorf("ticket after the close = %+v, want done without a working directory", tk)
	}
	if _, err := os.Stat(o.Config.Workspace.Root); err != nil {
		t.Errorf("the workspace root must stay: %v", err)
	}
	// A close of a ticket ochell never worked on is ignored.
	if r := o.JiraResolved("DEV-99"); r.Status != 200 || r.Body != "ignored" {
		t.Errorf("close of an unknown ticket: %d %q", r.Status, r.Body)
	}
}

// The repository mapping: a ticket of a mapped project runs for its
// repository, and a ticket that no entry matches is not started.
func TestRepoMapping(t *testing.T) {
	const backend, engine = "git@example.com:org/backend.git", "https://example.com/org/engine.git"
	o := Start(t, Options{Configure: func(c *config.Config) {
		c.Repos = []config.Repo{
			{Source: "jira", Project: "DEV", Repo: backend},
			{Source: "linear", Project: "ENG", Repo: engine},
		}
	}})
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Each mapped ticket runs, and its agent is told the repository.
	for id, repo := range map[string]string{
		o.JiraAssigned("DEV-30", "Mapped Jira ticket").TaskID(t):  backend,
		o.LinearCreated("ENG-30", "session-mapped", "").TaskID(t): engine,
	} {
		o.WaitRun(id, 15*time.Second)
		found := false
		for _, rec := range o.Records() {
			if got, _ := rec.Getenv("ORCH_TASK_ID"); got != id {
				continue
			}
			found = true
			if got, _ := rec.Getenv("ORCH_TASK_REPO"); got != repo {
				t.Errorf("%s: ORCH_TASK_REPO = %q, want %q", id, got, repo)
			}
			if !strings.Contains(rec.Stdin, "The repository for this ticket is "+repo+".") {
				t.Errorf("%s: the prompt does not name the repository:\n%s", id, rec.Stdin)
			}
		}
		if !found {
			t.Errorf("no record of run %s", id)
		}
	}
	if tk, _ := st.Ticket("jira", "DEV-30"); tk == nil || tk.Repo != backend {
		t.Errorf("stored ticket = %+v, want the repository", tk)
	}

	// A project that no entry names: nothing starts, and the ticket waits.
	runs := len(o.Records())
	if r := o.JiraAssigned("OPS-30", "Unmapped Jira ticket"); r.Status != 200 || r.Body != "not started: no repository is mapped to OPS-30" {
		t.Errorf("unmapped Jira ticket: %d %q", r.Status, r.Body)
	}
	if r := o.LinearCreated("DOC-30", "session-unmapped", ""); r.Status != 200 || r.Body != "not started: no repository is mapped to DOC-30" {
		t.Errorf("unmapped Linear ticket: %d %q", r.Status, r.Body)
	}
	for source, key := range map[string]string{"jira": "OPS-30", "linear": "DOC-30"} {
		if tk, _ := st.Ticket(source, key); tk == nil || tk.State != "waiting" || tk.Reason != "no_repo_mapping" || tk.Attempts != 0 {
			t.Errorf("%s %s = %+v, want waiting (no_repo_mapping) without an attempt", source, key, tk)
		}
	}
	// The Linear session is told why, so it does not look unanswered.
	acts := o.WaitActivities("session-unmapped", 1, 10*time.Second)
	if acts[0].Type != "elicitation" || !strings.Contains(acts[0].Body, "no repository is configured") {
		t.Errorf("the session got %+v", acts[0])
	}
	if !strings.Contains(o.Output(), "ticket not started: no repository is mapped to it") {
		t.Error("the refusal is not in ochell's log")
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(o.Records()); n != runs {
		t.Errorf("the agent was started for an unmapped ticket: %d runs, want %d", n, runs)
	}
}

// The run context: the prompt of a later attempt says which attempt it is,
// whether it continues the session, what the earlier attempt left behind,
// and which comment asked for the run.
func TestRunContextInThePrompt(t *testing.T) {
	const session = "3dc26999-bd50-487b-b445-cb41a233c6a2"
	const pr, branch = "https://github.com/example/repo/pull/7", "bot/ENG-8"
	const comment = "@agent the reviewer wants the error message translated as well"
	o := Start(t, Options{
		Script: []Step{
			{Print: `{"type":"system","subtype":"init","session_id":"` + session + `"}`},
			{Print: `{"type":"result","subtype":"success","result":"Opened a pull request.","session_id":"` + session + `"}`},
			Report("done", "Opened a pull request.", "pr_url", pr, "branch", branch),
		},
		Configure: func(c *config.Config) { c.Agent.Adapter = "claude" },
	})
	prompt := func(id string) string {
		t.Helper()
		o.WaitRun(id, 15*time.Second)
		for _, rec := range o.Records() {
			if got, _ := rec.Getenv("ORCH_TASK_ID"); got == id {
				return rec.Stdin
			}
		}
		t.Fatalf("no record of run %s", id)
		return ""
	}

	// A first attempt that nobody commented on has nothing to be told.
	first := prompt(o.LinearCreated("ENG-8", "session-first", "").TaskID(t))
	if strings.Contains(first, "Run context") || strings.Contains(first, "attempt") {
		t.Errorf("the first prompt holds a run context:\n%s", first)
	}

	// The ticket is free for a new run once the first one is reported.
	o.WaitActivities("session-first", 2, 10*time.Second)

	// Someone mentions the agent in a comment: the second attempt.
	second := prompt(o.LinearMentioned("ENG-8", "session-second", comment).TaskID(t))
	for _, want := range []string{
		"Run context from the orchestrator:",
		"This is attempt 2 on this ticket. It continues the agent session of the earlier attempt",
		"pushed the branch " + branch + " and opened the pull request " + pr,
		"<comment>\n" + comment + "\n</comment>",
	} {
		if !strings.Contains(second, want) {
			t.Errorf("the prompt of the resumed run lacks %q:\n%s", want, second)
		}
	}
}

// The claude adapter: the agent is called with the event stream as output,
// the final message (not the raw stream) goes to the ticket, the session id
// and the cost are stored, and the ticket's next run resumes the session.
func TestClaudeAdapterRecordsAndResumesTheSession(t *testing.T) {
	const session = "3dc26999-bd50-487b-b445-cb41a233c6a2"
	o := Start(t, Options{
		Script: []Step{
			{Eprint: `[claude-code:notice] a line on stderr that is not an event`},
			{Print: `{"type":"system","subtype":"init","session_id":"` + session + `","tools":["Bash"]}`},
			{Print: `{"type":"assistant","message":{"content":[{"type":"text","text":"Reading the ticket."},{"type":"tool_use","name":"Bash"}]},"session_id":"` + session + `"}`},
			{Print: `{"type":"result","subtype":"success","is_error":false,"result":"Opened PR #7.","session_id":"` + session + `","total_cost_usd":0.25,"usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":30,"cache_creation_input_tokens":40}}`},
			// No message of its own: the final message of the stream is used.
			Report("done", ""),
		},
		Configure: func(c *config.Config) {
			c.Agent.Adapter = "claude"
			c.Agent.Args = []string{"-p", "--permission-mode", "acceptEdits"}
		},
	})
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first := o.LinearCreated("ENG-81", "session-one", "").TaskID(t)
	o.WaitRun(first, 15*time.Second)
	acts := o.WaitActivities("session-one", 2, 10*time.Second)
	if acts[1].Type != "response" || acts[1].Body != "Opened PR #7." {
		t.Errorf("the ticket got %+v, want the agent's final message only", acts[1])
	}
	run, err := st.Run(first)
	if err != nil || run == nil {
		t.Fatalf("stored run: %v, %v", run, err)
	}
	if res := run.Result; res.SessionID != session || res.CostUSD != 0.25 || res.Message != "Opened PR #7." || res.Resumed ||
		res.Usage.InputTokens != 10 || res.Usage.OutputTokens != 20 || res.Usage.CacheReadTokens != 30 || res.Usage.CacheWriteTokens != 40 {
		t.Errorf("stored result = %+v", res)
	}
	if tk, _ := st.Ticket("linear", "ENG-81"); tk == nil || tk.AgentSession != session {
		t.Errorf("stored ticket = %+v, want the session id", tk)
	}

	// The ticket is delegated again: the same session goes on.
	second := o.LinearCreated("ENG-81", "session-two", "").TaskID(t)
	if run := o.WaitStored(st, second, 15*time.Second); !run.Result.Resumed || run.Attempt != 2 {
		t.Errorf("second run = %+v, want a resumed second attempt", run)
	}
	const start = "-p --permission-mode acceptEdits --output-format stream-json --verbose"
	var args []string
	for _, rec := range o.WaitRecords(2, 5*time.Second) {
		args = append(args, strings.Join(rec.Args, " "))
		if !strings.Contains(rec.Stdin, "ENG-81") {
			t.Errorf("the prompt was not on stdin: %q", rec.Stdin)
		}
	}
	slices.Sort(args)
	if len(args) != 2 || args[0] != start || args[1] != start+" --resume "+session {
		t.Errorf("agent arguments of the two runs:\n%s", strings.Join(args, "\n"))
	}
}

// The task queue, the record of what was running and the handled deliveries
// are in the store: they survive ochell being killed.
func TestQueueSurvivesRestart(t *testing.T) {
	o := Start(t, Options{Script: []Step{{Print: "working"}, {Sleep: "2s"}, {Print: "all done"}}})
	running := o.LinearCreated("ENG-40", "session-running", "").TaskID(t)
	rec := o.WaitRecords(1, 10*time.Second)[0]
	queued := o.JiraAssigned("DEV-40", "Waits for the worker").TaskID(t)
	if _, err := os.Stat(o.LogFile(queued)); err == nil {
		t.Fatal("the second task started although the only worker is busy")
	}

	o.Kill()
	// The crash leaves the agent behind; this test is not about that.
	syscall.Kill(-rec.PID, syscall.SIGKILL)
	o.Restart()

	// The task that was queued runs now.
	if run := o.WaitRun(queued, 20*time.Second); !strings.Contains(run.Footer, "outcome=finished") || !strings.Contains(run.Log, "all done") {
		t.Errorf("queued task after the restart: %s\n%s", run.Footer, run.Log)
	}
	// The ticket of the run that was cut short is told, and the run is
	// started again (TestKilledRunIsResumedWithTheRecoveryNote).
	acts := o.WaitActivities("session-running", 3, 20*time.Second)
	if acts[1].Type != "thought" || !strings.Contains(acts[1].Body, "queued again") || acts[2].Type == "error" {
		t.Errorf("activities of the interrupted run = %+v", acts)
	}
	if n := len(o.Records()); n != 3 {
		t.Errorf("the agent was started %d times in all, want 3: the two tickets, and the interrupted run again", n)
	}
	if _, err := os.Stat(o.LogFile(running)); err != nil {
		t.Errorf("log of the interrupted run: %v", err)
	}
	// A retry of a delivery from before the restart is still a duplicate.
	if r := o.Replay(); r.Status != 200 || r.Body != "duplicate delivery" {
		t.Errorf("replayed delivery after the restart: %d %q, want duplicate delivery", r.Status, r.Body)
	}
}

// The done-when of the recovery note: ochell is killed during a run. After
// the restart a new attempt starts in the same agent session and working
// directory, and its prompt has the recovery note.
func TestKilledRunIsResumedWithTheRecoveryNote(t *testing.T) {
	const session = "7f3c1a52-0a4e-4d0b-9f65-2f1f0a6b9c11"
	o := Start(t, Options{
		Script: []Step{
			{Print: `{"type":"system","subtype":"init","session_id":"` + session + `"}`},
			{Sleep: "2s"},
			{Print: `{"type":"result","subtype":"success","is_error":false,"result":"Opened PR #9.","session_id":"` + session + `"}`},
			Report("done", "Opened PR #9."),
		},
		Configure: func(c *config.Config) { c.Agent.Adapter = "claude" },
	})
	first := o.LinearCreated("ENG-51", "session-recovery", "").TaskID(t)
	rec := o.WaitRecords(1, 10*time.Second)[0]
	if strings.Contains(rec.Stdin, "restarted") {
		t.Fatalf("the first run got the recovery note:\n%s", rec.Stdin)
	}
	// The session is in the store before the run has ended.
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o.waitFor(5*time.Second, "the session of the running agent to be stored", func() bool {
		tk, _ := st.Ticket("linear", "ENG-51")
		return tk != nil && tk.AgentSession == session
	})

	o.Kill()
	// With the direct launcher a killed ochell leaves its agent behind.
	syscall.Kill(-rec.PID, syscall.SIGKILL)
	o.Restart()

	recs := o.WaitRecords(2, 15*time.Second)
	var second Record
	for _, r := range recs {
		if r.PID != rec.PID {
			second = r
		}
	}
	if !slices.Contains(second.Args, "--resume") || !slices.Contains(second.Args, session) {
		t.Errorf("arguments of the new attempt = %q, want --resume %s", second.Args, session)
	}
	if second.Dir != rec.Dir {
		t.Errorf("working directory of the new attempt = %q, want %q", second.Dir, rec.Dir)
	}
	for _, want := range []string{"This is attempt 2 on this ticket. It continues the agent session", "The orchestrator was restarted while you were working on this ticket", "before you repeat anything that has an effect outside the working directory"} {
		if !strings.Contains(second.Stdin, want) {
			t.Errorf("the prompt of the new attempt lacks %q:\n%s", want, second.Stdin)
		}
	}
	// The ticket: picked up, cut off and queued again, then the result.
	acts := o.WaitActivities("session-recovery", 3, 20*time.Second)
	if acts[1].Type != "thought" || !strings.Contains(acts[1].Body, "orchestrator was restarted") {
		t.Errorf("second activity = %+v, want the note that the run was cut off", acts[1])
	}
	if acts[2].Type != "response" || acts[2].Body != "Opened PR #9." {
		t.Errorf("third activity = %+v, want the result", acts[2])
	}
	if run, _ := st.Run(first); run == nil || run.Result.Outcome != "interrupted" {
		t.Errorf("the first run = %+v, want interrupted", run)
	}
	tk, _ := st.Ticket("linear", "ENG-51")
	if tk == nil || tk.State != "in_review" || tk.Attempts != 2 {
		t.Errorf("ticket = %+v, want in_review after two attempts", tk)
	}
}

// With the systemd launcher a shutdown stops the unit through the stop
// script. The stand-in has no cgroup; that a stop reaches every process of
// a unit is checked on the VM.
func TestSystemdLauncherShutdown(t *testing.T) {
	o := Start(t, Options{
		Script: []Step{{Print: "working"}, {Sleep: "10m"}},
		Configure: func(c *config.Config) {
			UseFakeSystemd(t, c)
			c.Agent.DrainTimeout = time.Second
			c.Agent.StopGrace = 2 * time.Second
		},
	})
	id := o.JiraAssigned("DEV-9", "Long run").TaskID(t)
	rec := o.WaitRecords(1, 10*time.Second)[0]
	o.Signal(syscall.SIGTERM)
	if code := o.WaitExit(20 * time.Second); code != 0 {
		t.Errorf("ochell exit code %d", code)
	}
	if run := o.WaitRun(id, time.Second); !strings.Contains(run.Footer, "outcome=stopped") {
		t.Errorf("run: %s", run.Footer)
	}
	expectAllGone(t, rec, 0)
}

// The systemd launcher with real systemd: the agent runs as another OS user
// and a stop reaches all its processes. CI has no systemd, so this runs on
// the VM only; see "Tests on the VM" in the README for the setup.
func TestSystemdLauncherOnVM(t *testing.T) {
	RequireVM(t)
	root := os.Getenv("OCHELL_E2E_VM_WORKSPACE")
	if root == "" {
		root = "/work"
	}
	const arg = "A${CLAUDE_CODE_OAUTH_TOKEN}B $HOME $$ 100%h"
	o := Start(t, Options{
		OtherAgentUser: true,
		Script: []Step{
			{TryRead: "{{dir}}/config.yaml"}, {TryRead: "{{dir}}/linear-token.json"},
			{WriteFile: &File{Path: "result.txt", Content: "done"}},
			{Spawn: &Spawn{Count: 2}}, {Spawn: &Spawn{Count: 1, Setsid: true}},
			{Print: "working"}, {Sleep: "10m"},
		},
		Configure: func(c *config.Config) {
			c.Agent.Launcher = "systemd"
			c.Agent.Args = []string{arg}
			c.Agent.Workdir = filepath.Join(root, "e2e-{{.Key}}-{{.ID}}")
			c.Agent.RunDir = filepath.Join(root, "e2e-runs")
			c.Agent.Timeout = 5 * time.Second
			c.Agent.StopGrace = 5 * time.Second
		},
	})

	id := o.LinearCreated("ENG-VM", "session-vm", "context with ${CLAUDE_CODE_OAUTH_TOKEN}").TaskID(t)
	run := o.WaitRun(id, 60*time.Second)
	if !strings.Contains(run.Footer, "outcome=timed_out") {
		t.Fatalf("run: %s\n%s", run.Footer, run.Log)
	}
	rec := o.WaitRecords(1, 5*time.Second)[0]
	if rec.UID == os.Getuid() {
		t.Errorf("the agent ran as ochell's own user (uid %d)", rec.UID)
	}
	if len(rec.Args) != 1 || rec.Args[0] != arg {
		t.Errorf("argument reached the agent as %q, want it unchanged: %q", rec.Args, arg)
	}
	if !strings.Contains(rec.Stdin, "context with ${CLAUDE_CODE_OAUTH_TOKEN}") {
		t.Errorf("prompt on stdin was changed:\n%s", rec.Stdin)
	}
	for _, f := range []string{"config.yaml", "linear-token.json"} {
		if got := rec.Reads[filepath.Join(o.Dir, f)]; got == "" || got == "ok" {
			t.Errorf("the agent could read ochell's %s: %q", f, got)
		}
	}
	if got := rec.Writes["result.txt"]; got != "ok" {
		t.Errorf("the agent could not write its working directory: %s", got)
	}
	expectAllGone(t, rec, 3)
}

// The same for a shutdown: ochell stops the unit, and systemd ends every
// process in it, including the child that left the process group.
func TestSystemdLauncherShutdownOnVM(t *testing.T) {
	RequireVM(t)
	root := os.Getenv("OCHELL_E2E_VM_WORKSPACE")
	if root == "" {
		root = "/work"
	}
	o := Start(t, Options{
		OtherAgentUser: true,
		Script:         spawning(Step{Spawn: &Spawn{Count: 2}}, Step{Spawn: &Spawn{Count: 1, Setsid: true}}),
		Configure: func(c *config.Config) {
			c.Agent.Launcher = "systemd"
			c.Agent.Workdir = filepath.Join(root, "e2e-{{.Key}}-{{.ID}}")
			c.Agent.RunDir = filepath.Join(root, "e2e-runs")
			c.Agent.DrainTimeout = time.Second
			c.Agent.StopGrace = 5 * time.Second
		},
	})
	id := o.LinearCreated("ENG-VM2", "session-vm-shutdown", "").TaskID(t)
	rec := waitChildren(t, o, 3)
	o.Signal(syscall.SIGTERM)
	if code := o.WaitExit(60 * time.Second); code != 0 {
		t.Errorf("ochell exit code %d", code)
	}
	if run := o.WaitRun(id, time.Second); !strings.Contains(run.Footer, "outcome=stopped") {
		t.Errorf("run: %s", run.Footer)
	}
	expectAllGone(t, rec, 3)
}

// ochell reaches Jira through its API client: it lists the tickets assigned
// to the bot and comments on one.
func TestJiraAPIAccess(t *testing.T) {
	o := Start(t, Options{})
	o.Jira.Add(jiratest.Issue{Key: "DEV-1", Summary: "Add retry to the payment client", Labels: []string{"backend"}})
	o.Jira.Add(jiratest.Issue{Key: "DEV-2", Summary: "Fix the login page"})
	o.Jira.Add(jiratest.Issue{Key: "DEV-3", Summary: "Update the docs"})

	out, code := o.Admin("jira-check")
	if code != 0 {
		t.Fatalf("jira-check: exit %d: %s", code, out)
	}
	for _, want := range []string{"3 open ticket(s)", "DEV-1", "Add retry to the payment client", "backend", "DEV-2", "DEV-3"} {
		if !strings.Contains(out, want) {
			t.Errorf("jira-check output missing %q:\n%s", want, out)
		}
	}
	if got := o.Jira.Comments("DEV-2"); len(got) != 0 {
		t.Errorf("jira-check without --comment-on wrote %q", got)
	}

	out, code = o.Admin("jira-check", "--comment-on", "DEV-2", "--text", "hello from ochell")
	if code != 0 {
		t.Fatalf("jira-check --comment-on: exit %d: %s", code, out)
	}
	if got := o.Jira.Comments("DEV-2"); !slices.Equal(got, []string{"hello from ochell"}) {
		t.Errorf("comments on DEV-2 = %q", got)
	}

	// A failure of the API is reported, not hidden.
	o.Jira.Fail(503)
	if out, code = o.Admin("jira-check"); code == 0 || !strings.Contains(out, "HTTP 503") {
		t.Errorf("jira-check against a failing site: exit %d: %s", code, out)
	}
}

// The Jira back-channel: a Jira ticket shows a comment when its run starts
// and a comment with the result when it ends.
func TestJiraStartAndFinishComments(t *testing.T) {
	t.Run("done", func(t *testing.T) {
		o := Start(t, Options{
			Script:    []Step{Report("done", "Added the retry and opened a pull request.", "pr_url", "https://github.com/example/repo/pull/7")},
			Configure: func(c *config.Config) { c.Sources.JiraAPI.ReviewStatus = "In Review" },
		})
		o.Jira.Add(jiratest.Issue{Key: "DEV-42", Status: "In Progress", Statuses: []string{"To Do", "In Review"}})
		id := o.JiraAssigned("DEV-42", "Add retry to the payment client").TaskID(t)
		o.WaitRun(id, 15*time.Second)
		got := o.WaitJiraComments("DEV-42", 2, 10*time.Second)
		if got[0] != "The digital employee started work on this ticket." {
			t.Errorf("start comment = %q", got[0])
		}
		for _, want := range []string{"ready for review", "Added the retry and opened a pull request.", "https://github.com/example/repo/pull/7"} {
			if !strings.Contains(got[1], want) {
				t.Errorf("finish comment missing %q: %q", want, got[1])
			}
		}
		o.waitFor(5*time.Second, "DEV-42 to move to In Review", func() bool { return o.Jira.Status("DEV-42") == "In Review" })
	})

	t.Run("a question, through Jira Automation", func(t *testing.T) {
		o := Start(t, Options{Script: []Step{Report("needs_input", "Which of the two login pages do you mean?")}})
		o.Jira.Add(jiratest.Issue{Key: "DEV-43", Status: "In Progress", Statuses: []string{"In Review"}})
		id := o.JiraAutomation("DEV-43", "Fix the login page").TaskID(t)
		o.WaitRun(id, 15*time.Second)
		got := o.WaitJiraComments("DEV-43", 2, 10*time.Second)
		if got[1] != "Which of the two login pages do you mean?" {
			t.Errorf("finish comment = %q, want the question", got[1])
		}
		if st := o.Jira.Status("DEV-43"); st != "In Progress" {
			t.Errorf("status = %q; a ticket that waits for an answer must not move", st)
		}
	})

	t.Run("a failed run", func(t *testing.T) {
		o := Start(t, Options{Script: []Step{{Eprint: "fatal: cannot reach the repository"}, Exit(3)}})
		o.Jira.Add(jiratest.Issue{Key: "DEV-44"})
		id := o.JiraAssigned("DEV-44", "Update the docs").TaskID(t)
		o.WaitRun(id, 15*time.Second)
		got := o.WaitJiraComments("DEV-44", 2, 10*time.Second)
		if !strings.Contains(got[1], "The agent failed (exit 3)") || !strings.Contains(got[1], "fatal: cannot reach the repository") {
			t.Errorf("finish comment = %q, want the failure and the output", got[1])
		}
	})
}

// A failure that is not the task's own, such as a rate limit, is retried by
// ochell after a wait, and counts as an attempt. A task failure is not.
func TestTransientFailureIsRetried(t *testing.T) {
	script := append(OnRun(1, Step{Eprint: "API Error: 429 rate limit exceeded, try again later"}, Exit(1)),
		Step{Print: "second try"}, Report("done", "Done on the second try."))
	o := Start(t, Options{
		Script: script,
		Configure: func(c *config.Config) {
			c.Agent.Retry.Backoff = time.Second
			c.Agent.Retry.MaxBackoff = time.Second
		},
	})
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first := o.LinearCreated("ENG-60", "session-retry", "").TaskID(t)
	failed := o.WaitStored(st, first, 15*time.Second)
	if failed.Result.Outcome != "failed" {
		t.Fatalf("first run = %+v, want failed", failed.Result)
	}
	ended := time.Now()

	// The ticket: picked up, the retry announced, then the result.
	acts := o.WaitActivities("session-retry", 3, 20*time.Second)
	if acts[1].Type != "thought" || !strings.Contains(acts[1].Body, "looks temporary") || !strings.Contains(acts[1].Body, "queued again") {
		t.Errorf("second activity = %+v, want the announcement of the retry", acts[1])
	}
	if acts[2].Type != "response" || acts[2].Body != "Done on the second try." {
		t.Errorf("third activity = %+v, want the result", acts[2])
	}
	if wait := acts[2].At.Sub(ended); wait < 800*time.Millisecond {
		t.Errorf("the retry ended %s after the failure, before the backoff of 1s was over", wait)
	}
	recs := o.WaitRecords(2, 5*time.Second)
	if len(recs) != 2 {
		t.Fatalf("the agent was started %d times, want 2", len(recs))
	}
	var prompts string
	for _, rec := range recs {
		prompts += rec.Stdin
	}
	for _, want := range []string{"This is attempt 2 on this ticket", "cut off by an error that had nothing to do with the ticket"} {
		if !strings.Contains(prompts, want) {
			t.Errorf("the prompt of the retry lacks %q", want)
		}
	}
	tk, _ := st.Ticket("linear", "ENG-60")
	if tk == nil || tk.State != "in_review" || tk.Attempts != 2 {
		t.Errorf("ticket = %+v, want in_review after two attempts", tk)
	}

	// A failure of the task itself is not retried.
	o2 := Start(t, Options{
		Script: []Step{{Eprint: "error: the tests do not pass"}, Exit(1)},
		Configure: func(c *config.Config) {
			c.Agent.Retry.Backoff, c.Agent.Retry.MaxBackoff = 100*time.Millisecond, 100*time.Millisecond
		},
	})
	id := o2.LinearCreated("ENG-61", "session-task-failure", "").TaskID(t)
	o2.WaitRun(id, 15*time.Second)
	if acts := o2.WaitActivities("session-task-failure", 2, 10*time.Second); acts[1].Type != "error" {
		t.Errorf("the ticket got %+v, want an error", acts[1])
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(o2.Records()); n != 1 {
		t.Errorf("the agent was started %d times, want 1: a task failure is not retried", n)
	}
}

// A retry that keeps failing stops at the attempt cap.
func TestRetryStopsAtTheAttemptCap(t *testing.T) {
	o := Start(t, Options{
		Script: []Step{{Eprint: "Overloaded"}, Exit(1)},
		Configure: func(c *config.Config) {
			c.Agent.MaxAttempts = 3
			c.Agent.Retry.Backoff, c.Agent.Retry.MaxBackoff = 50*time.Millisecond, 50*time.Millisecond
		},
	})
	o.LinearCreated("ENG-62", "session-cap", "").TaskID(t)
	// Picked up, two retries announced, then the error.
	acts := o.WaitActivities("session-cap", 4, 20*time.Second)
	if acts[1].Type != "thought" || acts[2].Type != "thought" || acts[3].Type != "error" {
		t.Errorf("activities = %+v, want two announced retries and then an error", acts)
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(o.Records()); n != 3 {
		t.Errorf("the agent was started %d times, want 3", n)
	}
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if tk, _ := st.Ticket("linear", "ENG-62"); tk == nil || tk.State != "failed" || tk.Attempts != 3 {
		t.Errorf("ticket = %+v, want failed after three attempts", tk)
	}
}

// An agent that writes no output for stall_timeout is killed and started
// again. After the last attempt the ticket waits for a human, reason stalled.
func TestStalledAgentIsKilled(t *testing.T) {
	o := Start(t, Options{
		Script: spawning(Step{Spawn: &Spawn{Count: 1}}),
		Configure: func(c *config.Config) {
			c.Agent.StallTimeout = 2 * time.Second
			c.Agent.StopGrace = time.Second
			c.Agent.MaxAttempts = 2
			c.Agent.Retry.Backoff, c.Agent.Retry.MaxBackoff = 100*time.Millisecond, 100*time.Millisecond
		},
	})
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first := o.LinearCreated("ENG-63", "session-stall", "").TaskID(t)
	run := o.WaitRun(first, 15*time.Second)
	if !strings.Contains(run.Footer, "outcome=stalled") || !strings.Contains(run.Footer, "wrote no output for 2s") {
		t.Errorf("first run: %s", run.Footer)
	}
	// Picked up, the second attempt announced, then the error.
	acts := o.WaitActivities("session-stall", 3, 20*time.Second)
	if acts[1].Type != "thought" || !strings.Contains(acts[1].Body, "wrote no output") || !strings.Contains(acts[1].Body, "queued again") {
		t.Errorf("second activity = %+v, want the announcement of the second attempt", acts[1])
	}
	if acts[2].Type != "error" || !strings.Contains(acts[2].Body, "waits for a human") {
		t.Errorf("third activity = %+v, want the error after the last attempt", acts[2])
	}
	recs := o.Records()
	if len(recs) != 2 {
		t.Fatalf("the agent was started %d times, want 2", len(recs))
	}
	// Each stalled agent is gone, with its child.
	for _, rec := range recs {
		expectAllGone(t, rec, 1)
	}
	if !strings.Contains(recs[0].Stdin+recs[1].Stdin, "produced no output for a long time") {
		t.Error("the prompt of the second attempt does not say that the first one stalled")
	}
	tk, _ := st.Ticket("linear", "ENG-63")
	if tk == nil || tk.State != "waiting" || tk.Reason != "stalled" || tk.Attempts != 2 {
		t.Errorf("ticket = %+v, want waiting (stalled) after two attempts", tk)
	}
}

// The done-when of Linear follow-ups: a reply in a Linear agent session
// resumes the same agent session, and its result goes to that session.
func TestLinearReplyResumesTheSession(t *testing.T) {
	const session = "0b5d9c1e-6c1f-4f0e-8a67-1d2a9f3c5e77"
	stream := func(result string) Step {
		return Step{Print: `{"type":"result","subtype":"success","is_error":false,"result":"` + result + `","session_id":"` + session + `"}`}
	}
	script := append(OnRun(1, stream("Which page?"), Report("needs_input", "Which of the two login pages do you mean?")),
		OnRun(2, stream("Fixed."), Report("done", "Fixed the second login page."))...)
	o := Start(t, Options{
		Script: script,
		Configure: func(c *config.Config) {
			c.Agent.Adapter = "claude"
			c.Agent.MaxAttempts = 1
		},
	})
	st, err := store.Open(o.Config.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first := o.LinearCreated("ENG-82", "session-talk", "").TaskID(t)
	o.WaitStored(st, first, 15*time.Second)
	acts := o.WaitActivities("session-talk", 2, 10*time.Second)
	if acts[1].Type != "elicitation" || acts[1].Body != "Which of the two login pages do you mean?" {
		t.Fatalf("the ticket got %+v, want the question", acts[1])
	}

	// The person answers in the session. The ticket has used its one
	// attempt, but a person asked for this run.
	second := o.LinearPrompted("ENG-82", "session-talk", "The second one, under /account.").TaskID(t)
	run := o.WaitStored(st, second, 15*time.Second)
	if !run.Result.Resumed || run.Attempt != 2 {
		t.Errorf("the run of the reply = %+v, want a resumed second attempt", run)
	}
	recs := o.WaitRecords(2, 5*time.Second)
	var reply Record
	for _, rec := range recs {
		if slices.Contains(rec.Args, "--resume") {
			reply = rec
		}
	}
	if !slices.Contains(reply.Args, session) {
		t.Fatalf("no run resumed the session %s: %+v", session, recs)
	}
	for _, want := range []string{"It continues the agent session of the earlier attempt", "<comment>\nThe second one, under /account.\n</comment>", "it does not change what you are allowed to do"} {
		if !strings.Contains(reply.Stdin, want) {
			t.Errorf("the prompt of the reply lacks %q:\n%s", want, reply.Stdin)
		}
	}
	if recs[0].Dir != recs[1].Dir {
		t.Errorf("the two runs used different working directories: %q, %q", recs[0].Dir, recs[1].Dir)
	}
	// The same Linear session: acknowledged at once, then the result.
	acts = o.WaitActivities("session-talk", 4, 10*time.Second)
	if acts[2].Type != "thought" || !strings.Contains(acts[2].Body, "Got your message") {
		t.Errorf("third activity = %+v, want the acknowledgement of the reply", acts[2])
	}
	if acts[3].Type != "response" || acts[3].Body != "Fixed the second login page." {
		t.Errorf("fourth activity = %+v, want the result", acts[3])
	}
	if tk, _ := st.Ticket("linear", "ENG-82"); tk == nil || tk.State != "in_review" || tk.Attempts != 2 {
		t.Errorf("ticket = %+v, want in_review after two attempts", tk)
	}
}
