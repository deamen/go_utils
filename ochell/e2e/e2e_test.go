//go:build unix

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	o := Start(t, Options{Script: []Step{{Print: "working"}, {Sleep: "3s"}, {Print: "all done"}}})
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
	// The ticket is told that the run was cut short.
	acts := o.Linear.Activities("session-shutdown")
	if len(acts) != 2 || acts[1].Type != "error" || !strings.Contains(acts[1].Body, "shutting down") {
		t.Errorf("activities = %+v, want an error that names the shutdown", acts)
	}
}

// An agent that finishes within drain_timeout is not cut short by a
// shutdown, and no new webhook is accepted meanwhile.
func TestShutdownWaitsForRunningAgent(t *testing.T) {
	o := Start(t, Options{
		Script:    []Step{{Print: "started"}, {Sleep: "1500ms"}, {Print: "all done"}},
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
	// The run that was cut short is not started again, and its ticket is told.
	acts := o.WaitActivities("session-running", 2, 10*time.Second)
	if acts[1].Type != "error" || !strings.Contains(acts[1].Body, "ochell stopped while the agent was running") {
		t.Errorf("activities of the interrupted run = %+v", acts)
	}
	if n := len(o.Records()); n != 2 {
		t.Errorf("the agent was started %d times in all, want 2: the interrupted run must not start again", n)
	}
	if _, err := os.Stat(o.LogFile(running)); err != nil {
		t.Errorf("log of the interrupted run: %v", err)
	}
	// A retry of a delivery from before the restart is still a duplicate.
	if r := o.Replay(); r.Status != 200 || r.Body != "duplicate delivery" {
		t.Errorf("replayed delivery after the restart: %d %q, want duplicate delivery", r.Status, r.Body)
	}
	// The interrupted ticket can be delegated again.
	again := o.LinearCreated("ENG-40", "session-again", "").TaskID(t)
	if run := o.WaitRun(again, 20*time.Second); !strings.Contains(run.Footer, "outcome=finished") {
		t.Errorf("new run of the interrupted ticket: %s", run.Footer)
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
