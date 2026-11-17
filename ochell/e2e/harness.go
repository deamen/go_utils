//go:build unix

// Package e2e is the end-to-end test harness. It starts a real ochell
// process with a scripted fake agent (see fakeagent), a fake Linear API, a
// fake Jira site and a fake GitHub API,
// and sends it signed webhooks, so the full loop can be tested without a
// real agent or tracker.
//
// The harness uses the direct launcher. Tests that need the systemd launcher
// call RequireVM, which skips them unless OCHELL_E2E_VM=1: CI has no systemd,
// so they run on the VM.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"ochell/internal/auth"
	"ochell/internal/config"
	"ochell/internal/github/githubtest"
	"ochell/internal/source/linear/lineartest"
	"ochell/internal/store"
	"ochell/internal/tracker/jiraapi/jiratest"
)

// Secrets and ids the harness configures ochell with.
const (
	JiraSecret      = "e2e-jira-secret"
	AutomationToken = "e2e-automation-token"
	LinearSecret    = "e2e-linear-secret"
	LinearToken     = "e2e-linear-access-token"
	BotAccountID    = "712020:digital-employee"
	// AgentToken is in the environment file of UseFakeSystemd.
	AgentToken = "e2e-agent-token"
	// LinearAppUserID is the Linear user of the agent app itself.
	LinearAppUserID = "app-user-0000"
	// GitHubSecret is the secret of the GitHub webhook, GitHubRepo the one
	// repository of the GitHub source, GitHubBot the login of the digital
	// employee there and GitHubHuman who assigns the issues, unless
	// Ochell.Actor says otherwise.
	GitHubSecret = "e2e-github-secret"
	GitHubRepo   = "acme/shop"
	GitHubBot    = githubtest.Bot
	GitHubHuman  = "alice"
	// HumanAccountID is who assigns the tickets, unless Ochell.Actor says
	// otherwise: the Jira accountId and the Linear user id of the payloads.
	HumanAccountID = "557058:human"
)

// RequireVM skips a test that needs the systemd launcher and its sudo
// scripts. Set OCHELL_E2E_VM=1 on a VM that has them installed.
func RequireVM(t *testing.T) {
	t.Helper()
	if os.Getenv("OCHELL_E2E_VM") != "1" {
		t.Skip("VM-only test: needs the systemd launcher; set OCHELL_E2E_VM=1 on the VM")
	}
}

// UseFakeSystemd selects the systemd launcher with the real launch and stop
// scripts, and stand-ins for systemd-run and systemctl, so the path through
// the scripts is covered where there is no systemd. The agent still runs as
// the current user. It returns the workspace root.
func UseFakeSystemd(t *testing.T, c *config.Config) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the scripts ignore the stand-ins when run as root")
	}
	abs := func(rel string) string {
		p, err := filepath.Abs(rel)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, state := filepath.Join(dir, "work"), filepath.Join(dir, "systemd")
	for _, d := range []string{root, state} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	envFile := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envFile, []byte("AGENT_TOKEN="+AgentToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "launcher.conf")
	settings := "AGENT_USER=" + u.Username + "\nWORKSPACE_ROOT=" + root + "\nENV_FILE=" + envFile + "\nALLOWED_ENV='^FAKEAGENT_[A-Z_]+$'\n"
	if err := os.WriteFile(conf, []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	overrides := []string{
		"/usr/bin/env",
		"OCHELL_LAUNCHER_CONF=" + conf,
		"OCHELL_LAUNCHER_SYSTEMD_RUN=" + abs("../internal/launcher/testdata/fake-systemd-run"),
		"OCHELL_LAUNCHER_SYSTEMCTL=" + abs("../internal/launcher/testdata/fake-systemctl"),
		"FAKE_SYSTEMD_DIR=" + state,
	}
	c.Agent.Launcher = "systemd"
	c.Agent.Systemd.LaunchCommand = append(append([]string{}, overrides...), abs("../scripts/ochell-launch"))
	c.Agent.Systemd.StopCommand = append(append([]string{}, overrides...), abs("../scripts/ochell-stop"))
	c.Agent.Workdir = filepath.Join(root, "{{.Source}}-{{.Key}}")
	c.Agent.RunDir = filepath.Join(root, "runs")
	return root
}

// Step and Spawn mirror the fake agent's script format (fakeagent/main.go).
type Step struct {
	Print      string `json:"print,omitempty"`
	Eprint     string `json:"eprint,omitempty"`
	Sleep      string `json:"sleep,omitempty"`
	Spawn      *Spawn `json:"spawn,omitempty"`
	WriteFile  *File  `json:"write_file,omitempty"`
	TryRead    string `json:"try_read,omitempty"`
	WaitFile   string `json:"wait_file,omitempty"`
	IgnoreTerm bool   `json:"ignore_term,omitempty"`
	Exit       *int   `json:"exit,omitempty"`
	OnRun      int    `json:"on_run,omitempty"`
}

type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type Spawn struct {
	Count      int  `json:"count"`
	Setsid     bool `json:"setsid,omitempty"`
	IgnoreTerm bool `json:"ignore_term,omitempty"`
}

// Exit builds an exit step.
func Exit(code int) Step { return Step{Exit: &code} }

// OnRun limits steps to the n-th run of the fake agent, counting from 1.
func OnRun(n int, steps ...Step) []Step {
	for i := range steps {
		steps[i].OnRun = n
	}
	return steps
}

// Report builds the step in which the agent writes its result file, as the
// prompt tells it to. More fields are given as name, value pairs.
func Report(status, message string, more ...string) Step {
	fields := map[string]string{"status": status, "message": message}
	for i := 0; i+1 < len(more); i += 2 {
		fields[more[i]] = more[i+1]
	}
	raw, _ := json.Marshal(fields)
	return Step{WriteFile: &File{Path: "$ORCH_RESULT_FILE", Content: string(raw)}}
}

// Record is what the fake agent saw when it was started.
type Record struct {
	PID      int      `json:"pid"`
	UID      int      `json:"uid"`
	Args     []string `json:"args"`
	Env      []string `json:"env"`
	Stdin    string   `json:"stdin"`
	Dir      string   `json:"dir"`
	Children []int    `json:"children,omitempty"`
	// Reads and Writes hold "ok" or the error of each try_read and
	// write_file step, by path.
	Reads  map[string]string `json:"reads,omitempty"`
	Writes map[string]string `json:"writes,omitempty"`
}

// Getenv returns the value of name in the agent's environment.
func (r Record) Getenv(name string) (string, bool) {
	for _, kv := range r.Env {
		if k, v, _ := strings.Cut(kv, "="); k == name {
			return v, true
		}
	}
	return "", false
}

// Options configure one ochell instance.
type Options struct {
	// Script is played by the fake agent on every run. Empty means: print
	// one line and exit 0. "{{dir}}" in a step is replaced with Ochell.Dir,
	// which holds config.yaml and linear-token.json.
	Script []Step
	// Configure changes the configuration before ochell starts.
	Configure func(c *config.Config)
	// Policy, when set, is the content of the policy file that ochell is
	// started with (policy.file).
	Policy string
	// Env is added to the environment of the ochell process.
	Env []string
	// GitHub turns the GitHub source on, for the issues of GitHubRepo, with
	// the fake GitHub API as its tracker. It is off otherwise.
	GitHub bool
	// OtherAgentUser prepares for an agent that runs as another OS user (the
	// systemd launcher on the VM): it must be able to read its script and
	// write its record, but not ochell's configuration.
	OtherAgentUser bool
}

// Ochell is a running ochell process and the fakes around it.
type Ochell struct {
	URL    string
	Dir    string
	Config *config.Config
	Linear *FakeLinear
	// Jira is the fake Jira site that the Jira API client talks to.
	Jira *jiratest.Server
	// GitHub is the fake GitHub API: the issues that the GitHub source
	// asks about and comments on.
	GitHub *githubtest.Server
	// Actor is the user who assigns the tickets in the payloads that are
	// sent from now on. Empty: HumanAccountID.
	Actor string
	// Labels and IssueType are those of the tickets in the payloads that
	// are sent from now on. A Linear issue has no type.
	Labels    []string
	IssueType string
	// Priority is the name of the priority of the Jira tickets in the
	// payloads that are sent from now on; empty: the payload has none.
	Priority string

	t         *testing.T
	bin       string
	cfgFile   string
	env       []string
	cmd       *exec.Cmd
	out       *lockedBuffer
	recordDir string
	exited    chan struct{}
	exitErr   error
	last      func() Response
}

var (
	buildOnce sync.Once
	buildDir  string
	buildErr  error
	prebuilt  bool
)

// build compiles ochell and the fake agent once per test binary.
func build() (ochell, agent string, err error) {
	buildOnce.Do(func() {
		// On the VM there may be no Go toolchain: use binaries built elsewhere.
		if dir := os.Getenv("OCHELL_E2E_BIN_DIR"); dir != "" {
			prebuilt = true
			buildDir, buildErr = filepath.Abs(dir)
			return
		}
		buildDir, buildErr = os.MkdirTemp("", "ochell-e2e-bin")
		if buildErr != nil {
			return
		}
		for name, pkg := range map[string]string{"ochell": "ochell", "fakeagent": "ochell/e2e/fakeagent"} {
			args := []string{"build"}
			if raceEnabled {
				args = append(args, "-race")
			}
			args = append(args, "-o", filepath.Join(buildDir, name), pkg)
			if out, err := exec.Command("go", args...).CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("go build %s: %v\n%s", pkg, err, out)
				return
			}
		}
	})
	return filepath.Join(buildDir, "ochell"), filepath.Join(buildDir, "fakeagent"), buildErr
}

// RemoveBinaries deletes the compiled binaries; call it from TestMain.
func RemoveBinaries() {
	if buildDir != "" && !prebuilt {
		os.RemoveAll(buildDir)
	}
}

// Start runs ochell with every source enabled and the fake agent as the
// agent command, and waits until it answers on /healthz. The process is
// stopped when the test ends.
func Start(t *testing.T, opts Options) *Ochell {
	t.Helper()
	ochellBin, agentBin, err := build()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	o := &Ochell{t: t, Dir: dir, bin: ochellBin, env: opts.Env, recordDir: filepath.Join(dir, "records"), out: &lockedBuffer{}}
	for _, d := range []string{o.recordDir, filepath.Join(dir, "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if opts.OtherAgentUser {
		// The test's temporary directories are private to the current user.
		for _, d := range []string{filepath.Dir(dir), dir} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(o.recordDir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	o.Linear = lineartest.New(t, LinearToken)
	o.Jira = jiratest.New(t)
	o.GitHub = githubtest.New(t)

	port := freePort(t)
	cfg := config.Default()
	cfg.LogLevel = "debug"
	cfg.HTTP = config.Listener{Enabled: true, Address: "127.0.0.1", Port: port}
	cfg.Store.Path = filepath.Join(dir, "ochell.db")
	// Off, so that only what a test sends starts a run. The tests of the
	// poller turn it on.
	cfg.Poller.Interval = 0
	cfg.Agent.Command = agentBin
	cfg.Agent.Args = nil
	cfg.Agent.PromptVia = "stdin"
	cfg.Agent.Workdir = filepath.Join(dir, "work", "{{.Source}}-{{.Key}}")
	cfg.Agent.LogDir = filepath.Join(dir, "logs")
	cfg.Agent.RunDir = filepath.Join(dir, "runs")
	cfg.Agent.Timeout = time.Minute
	cfg.Agent.Env = map[string]string{"FAKEAGENT_RECORD_DIR": o.recordDir}
	if len(opts.Script) > 0 {
		raw, err := json.Marshal(map[string]any{"steps": opts.Script})
		if err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(dir, "script.json")
		raw = bytes.ReplaceAll(raw, []byte("{{dir}}"), []byte(dir))
		if err := os.WriteFile(script, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.Agent.Env["FAKEAGENT_SCRIPT"] = script
	}
	cfg.Sources.JiraWebhook.Enabled = true
	cfg.Sources.JiraWebhook.Secret = JiraSecret
	cfg.Sources.JiraWebhook.BotAccountID = BotAccountID
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = AutomationToken
	cfg.Sources.JiraAutomation.BotAccountID = BotAccountID
	cfg.Sources.JiraAPI = config.JiraAPI{BaseURL: o.Jira.URL, Email: jiratest.Email, Token: jiratest.Token}
	cfg.Sources.Linear.Enabled = true
	cfg.Sources.Linear.Secret = LinearSecret
	cfg.Sources.Linear.ClientID = "e2e-client-id"
	cfg.Sources.Linear.ClientSecret = "e2e-client-secret"
	cfg.Sources.Linear.TokenFile = filepath.Join(dir, "linear-token.json")
	cfg.Sources.Linear.APIURL = o.Linear.URL
	cfg.Sources.Linear.TokenURL = o.Linear.URL + "/oauth/token"
	// Off, so that a test counts only the activities it is about. The
	// test of the tool activities turns them on.
	cfg.Sources.Linear.ToolActivityInterval = 0
	if opts.GitHub {
		cfg.GitHub.APIURL = o.GitHub.URL
		cfg.GitHub.BotLogin = GitHubBot
		cfg.Sources.GitHub.Enabled = true
		cfg.Sources.GitHub.Secret = GitHubSecret
		cfg.Sources.GitHub.Token = githubtest.IssuesToken
		cfg.Sources.GitHub.Repos = []config.GitHubRepo{{Repo: GitHubRepo}}
	}
	if opts.Policy != "" {
		cfg.Policy.File = filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(cfg.Policy.File, []byte(opts.Policy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if opts.Configure != nil {
		opts.Configure(cfg)
	}
	o.Config = cfg

	token, _ := json.Marshal(map[string]string{"access_token": LinearToken, "token_type": "Bearer"})
	if err := os.WriteFile(cfg.Sources.Linear.TokenFile, token, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	o.cfgFile = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(o.cfgFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	o.URL = fmt.Sprintf("http://127.0.0.1:%d", port)
	t.Cleanup(func() {
		select {
		case <-o.exited:
		default:
			o.cmd.Process.Kill()
			<-o.exited
		}
		if t.Failed() {
			t.Logf("ochell output:\n%s", o.out.String())
		}
	})
	o.run()
	return o
}

func (o *Ochell) actor() string {
	if o.Actor != "" {
		return o.Actor
	}
	return HumanAccountID
}

// Admin runs a subcommand of ochell with the configuration of the running
// process, as an operator would: an admin command (pause, resume, status,
// reset) or jira-check. It returns what the command printed and its exit
// code.
func (o *Ochell) Admin(args ...string) (string, int) {
	o.t.Helper()
	cmd := exec.Command(o.bin, append(args, "--config", o.cfgFile)...)
	cmd.Dir = o.Dir
	out, err := cmd.CombinedOutput()
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		o.t.Fatal(err)
	}
	return strings.TrimSpace(string(out)), cmd.ProcessState.ExitCode()
}

// run starts the ochell process and waits until it answers on /healthz.
func (o *Ochell) run() {
	o.t.Helper()
	o.exited = make(chan struct{})
	o.cmd = exec.Command(o.bin, "serve", "--config", o.cfgFile)
	o.cmd.Dir = o.Dir
	o.cmd.Env = append(os.Environ(), o.env...)
	o.cmd.Stdout, o.cmd.Stderr = o.out, o.out
	if err := o.cmd.Start(); err != nil {
		o.t.Fatal(err)
	}
	cmd, exited := o.cmd, o.exited
	go func() {
		o.exitErr = cmd.Wait()
		close(exited)
	}()
	o.waitFor(10*time.Second, "ochell to answer on /healthz", func() bool {
		select {
		case <-o.exited:
			o.t.Fatalf("ochell exited during start: %v\n%s", o.exitErr, o.out.String())
		default:
		}
		resp, err := http.Get(o.URL + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

// Kill ends the ochell process at once, as a crash would: nothing is shut
// down, and a running agent is left behind.
func (o *Ochell) Kill() {
	o.t.Helper()
	if err := o.cmd.Process.Kill(); err != nil {
		o.t.Fatal(err)
	}
	<-o.exited
}

// Restart starts ochell again after it has exited, with the same
// configuration, store and logs.
func (o *Ochell) Restart() {
	o.t.Helper()
	select {
	case <-o.exited:
	default:
		o.t.Fatal("Restart: ochell is still running")
	}
	o.run()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitFor polls cond until it is true or fails the test after timeout.
func (o *Ochell) waitFor(timeout time.Duration, what string, cond func() bool) {
	o.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			o.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Response is ochell's answer to a webhook.
type Response struct {
	Status int
	Body   string
}

var queued = regexp.MustCompile(`^queued (\S+)`)

// TaskID returns the id from a "queued <task id>" answer, or fails the test.
func (r Response) TaskID(t *testing.T) string {
	t.Helper()
	m := queued.FindStringSubmatch(r.Body)
	if r.Status != http.StatusOK || m == nil {
		t.Fatalf("webhook was not queued: %d %q", r.Status, r.Body)
	}
	return m[1]
}

// Post sends a request body with headers to one of ochell's paths.
func (o *Ochell) Post(path string, body []byte, headers map[string]string) Response {
	o.t.Helper()
	o.last = func() Response { return o.post(path, body, headers) }
	return o.post(path, body, headers)
}

// Replay sends the last request again, byte for byte, as a sender that
// retries a delivery does.
func (o *Ochell) Replay() Response {
	o.t.Helper()
	if o.last == nil {
		o.t.Fatal("Replay: nothing was sent yet")
	}
	return o.last()
}

func (o *Ochell) post(path string, body []byte, headers map[string]string) Response {
	o.t.Helper()
	req, err := http.NewRequest(http.MethodPost, o.URL+path, bytes.NewReader(body))
	if err != nil {
		o.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		o.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return Response{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
}

var deliverySeq struct {
	sync.Mutex
	n int
}

func nextDelivery() string {
	deliverySeq.Lock()
	defer deliverySeq.Unlock()
	deliverySeq.n++
	return fmt.Sprintf("e2e-delivery-%d-%d", os.Getpid(), deliverySeq.n)
}

// JiraAssigned sends a signed Jira system webhook: the ticket was assigned
// to the digital employee.
func (o *Ochell) JiraAssigned(key, summary string) Response {
	o.t.Helper()
	fields := map[string]any{
		"summary":  summary,
		"assignee": map[string]string{"accountId": BotAccountID},
	}
	if len(o.Labels) > 0 {
		fields["labels"] = o.Labels
	}
	if o.IssueType != "" {
		fields["issuetype"] = map[string]string{"name": o.IssueType}
	}
	if o.Priority != "" {
		fields["priority"] = map[string]string{"name": o.Priority}
	}
	body, err := json.Marshal(map[string]any{
		"timestamp":             time.Now().UnixMilli(),
		"webhookEvent":          "jira:issue_updated",
		"issue_event_type_name": "issue_assigned",
		"user":                  map[string]string{"accountId": o.actor()},
		"issue": map[string]any{
			"id": "10042", "key": key,
			"self":   "https://example.atlassian.net/rest/api/2/issue/10042",
			"fields": fields,
		},
		"changelog": map[string]any{"items": []map[string]string{
			{"field": "assignee", "fieldId": "assignee", "from": "557058:human", "to": BotAccountID},
		}},
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.JiraWebhook.Path, body, map[string]string{
		"X-Hub-Signature":                "sha256=" + auth.SignHex(JiraSecret, body),
		"X-Atlassian-Webhook-Identifier": nextDelivery(),
	})
}

// JiraUpdated sends a signed Jira system webhook: something on the ticket
// changed that is not its assignee, such as its labels (Ochell.Labels) or
// its issue type (Ochell.IssueType).
func (o *Ochell) JiraUpdated(key string) Response {
	o.t.Helper()
	fields := map[string]any{
		"summary":  "Summary of " + key,
		"assignee": map[string]string{"accountId": BotAccountID},
		"labels":   o.Labels,
	}
	if o.IssueType != "" {
		fields["issuetype"] = map[string]string{"name": o.IssueType}
	}
	body, err := json.Marshal(map[string]any{
		"timestamp":    time.Now().UnixMilli(),
		"webhookEvent": "jira:issue_updated",
		"user":         map[string]string{"accountId": o.actor(), "displayName": "Someone"},
		"issue": map[string]any{
			"id": "10042", "key": key,
			"self":   "https://example.atlassian.net/rest/api/2/issue/10042",
			"fields": fields,
		},
		"changelog": map[string]any{"items": []map[string]any{
			{"field": "labels", "fieldId": "labels", "fromString": "", "toString": strings.Join(o.Labels, " ")},
		}},
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.JiraWebhook.Path, body, map[string]string{
		"X-Hub-Signature":                "sha256=" + auth.SignHex(JiraSecret, body),
		"X-Atlassian-Webhook-Identifier": nextDelivery(),
	})
}

// LinearUpdated sends a signed Linear "Issue" update: something on the
// issue changed, such as its labels (Ochell.Labels).
func (o *Ochell) LinearUpdated(key string) Response {
	o.t.Helper()
	body, err := json.Marshal(map[string]any{
		"type": "Issue", "action": "update",
		"organizationId":   "org-0000",
		"appUserId":        LinearAppUserID,
		"actor":            map[string]string{"id": o.actor()},
		"data":             map[string]any{"identifier": key, "labels": linearLabels(o.Labels)},
		"updatedFrom":      map[string]any{"labelIds": []string{}},
		"webhookTimestamp": time.Now().UnixMilli(),
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.Linear.Path, body, map[string]string{
		"Linear-Signature": auth.SignHex(LinearSecret, body),
		"Linear-Delivery":  nextDelivery(),
	})
}

// JiraResolved sends a signed Jira system webhook: the ticket was resolved.
func (o *Ochell) JiraResolved(key string) Response {
	o.t.Helper()
	body, err := json.Marshal(map[string]any{
		"timestamp":    time.Now().UnixMilli(),
		"webhookEvent": "jira:issue_updated",
		"user":         map[string]string{"accountId": o.actor()},
		"issue":        map[string]any{"id": "10042", "key": key},
		"changelog": map[string]any{"items": []map[string]string{
			{"field": "status", "fieldId": "status", "from": "3", "to": "10001"},
			{"field": "resolution", "fieldId": "resolution", "to": "10000", "toString": "Done"},
		}},
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.JiraWebhook.Path, body, map[string]string{
		"X-Hub-Signature":                "sha256=" + auth.SignHex(JiraSecret, body),
		"X-Atlassian-Webhook-Identifier": nextDelivery(),
	})
}

// JiraUnassigned sends a signed Jira system webhook: someone took the
// ticket away from the digital employee.
func (o *Ochell) JiraUnassigned(key string) Response {
	o.t.Helper()
	body, err := json.Marshal(map[string]any{
		"timestamp":    time.Now().UnixMilli(),
		"webhookEvent": "jira:issue_updated",
		"user":         map[string]string{"accountId": o.actor(), "displayName": "Someone"},
		"issue":        map[string]any{"id": "10042", "key": key},
		"changelog": map[string]any{"items": []map[string]any{
			{"field": "assignee", "fieldId": "assignee", "from": BotAccountID, "to": nil},
		}},
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.JiraWebhook.Path, body, map[string]string{
		"X-Hub-Signature":                "sha256=" + auth.SignHex(JiraSecret, body),
		"X-Atlassian-Webhook-Identifier": nextDelivery(),
	})
}

// JiraCommented sends a signed Jira system webhook: someone added a comment
// to a ticket that is assigned to the digital employee. An empty author is
// the person who assigns the tickets; BotAccountID is the bot itself.
func (o *Ochell) JiraCommented(key, author, text string) Response {
	o.t.Helper()
	if author == "" {
		author = o.actor()
	}
	body, err := json.Marshal(map[string]any{
		"timestamp":    time.Now().UnixMilli(),
		"webhookEvent": "comment_created",
		"comment": map[string]any{
			"id": "20001", "body": text,
			"author": map[string]string{"accountId": author, "displayName": "Someone"},
		},
		"issue": map[string]any{
			"id": "10042", "key": key,
			"self": "https://example.atlassian.net/rest/api/2/issue/10042",
			"fields": map[string]any{
				"summary":  "Summary of " + key,
				"assignee": map[string]string{"accountId": BotAccountID},
			},
		},
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.JiraWebhook.Path, body, map[string]string{
		"X-Hub-Signature":                "sha256=" + auth.SignHex(JiraSecret, body),
		"X-Atlassian-Webhook-Identifier": nextDelivery(),
	})
}

// GitHubEvent sends a signed GitHub webhook of the kind event ("issues",
// "issue_comment", "pull_request") about the issue number of repo, as
// owner/name. The sender is Ochell.Actor, or GitHubHuman; the issue is
// assigned to the digital employee, was opened by GitHubHuman and has
// Ochell.Labels. more is added to the payload, and to the issue under
// "issue".
func (o *Ochell) GitHubEvent(event, action, repo string, number int, more map[string]any) Response {
	o.t.Helper()
	sender := o.Actor
	if sender == "" {
		sender = GitHubHuman
	}
	labels := []map[string]string{}
	for _, l := range o.Labels {
		labels = append(labels, map[string]string{"name": l})
	}
	kind := "issues"
	if event == "pull_request" {
		kind = "pull"
	}
	issue := map[string]any{
		"number": number, "title": fmt.Sprintf("Issue %d", number), "state": "open",
		"html_url":  fmt.Sprintf("https://github.com/%s/%s/%d", repo, kind, number),
		"user":      map[string]string{"login": GitHubHuman},
		"labels":    labels,
		"assignees": []map[string]string{{"login": GitHubBot}},
		// As on GitHub, where every change of an issue moves this time: two
		// deliveries about one issue are not the same bytes.
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	payload := map[string]any{
		"action":     action,
		"repository": map[string]string{"full_name": repo},
		"sender":     map[string]string{"login": sender},
	}
	for k, v := range more {
		if k == "issue" {
			for ik, iv := range v.(map[string]any) {
				issue[ik] = iv
			}
			continue
		}
		payload[k] = v
	}
	if event == "pull_request" {
		payload["pull_request"] = issue
	} else {
		payload["issue"] = issue
	}
	body, err := json.Marshal(payload)
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.GitHub.Path, body, map[string]string{
		"X-GitHub-Event":      event,
		"X-GitHub-Delivery":   nextDelivery(),
		"X-Hub-Signature-256": "sha256=" + auth.SignHex(GitHubSecret, body),
	})
}

// GitHubAssigned sends a signed GitHub webhook: the issue number of
// GitHubRepo was assigned to the digital employee.
func (o *Ochell) GitHubAssigned(number int, title string) Response {
	o.t.Helper()
	return o.GitHubEvent("issues", "assigned", GitHubRepo, number, map[string]any{
		"assignee": map[string]string{"login": GitHubBot},
		"issue":    map[string]any{"title": title},
	})
}

// GitHubUnassigned sends a signed GitHub webhook: someone took the issue
// away from the digital employee.
func (o *Ochell) GitHubUnassigned(number int) Response {
	o.t.Helper()
	return o.GitHubEvent("issues", "unassigned", GitHubRepo, number, map[string]any{
		"assignee": map[string]string{"login": GitHubBot},
		"issue":    map[string]any{"assignees": []map[string]string{}},
	})
}

// GitHubClosed sends a signed GitHub webhook: the issue was closed.
func (o *Ochell) GitHubClosed(number int) Response {
	o.t.Helper()
	return o.GitHubEvent("issues", "closed", GitHubRepo, number, map[string]any{"issue": map[string]any{"state": "closed"}})
}

// GitHubCommented sends a signed GitHub webhook: someone added a comment
// to an issue that is assigned to the digital employee. An empty author is
// the person who assigns the issues; GitHubBot is the bot itself.
func (o *Ochell) GitHubCommented(number int, author, text string) Response {
	o.t.Helper()
	if author == "" {
		author = o.Actor
	}
	if author == "" {
		author = GitHubHuman
	}
	return o.GitHubEvent("issue_comment", "created", GitHubRepo, number, map[string]any{
		"sender":  map[string]string{"login": author},
		"comment": map[string]any{"id": 20001, "body": text, "user": map[string]string{"login": author}},
	})
}

// WaitIssueComments waits until the issue number of GitHubRepo on the fake
// GitHub has n comments, and returns their texts.
func (o *Ochell) WaitIssueComments(number, n int, timeout time.Duration) []string {
	o.t.Helper()
	owner, repo, _ := strings.Cut(GitHubRepo, "/")
	var got []string
	o.waitFor(timeout, fmt.Sprintf("%d comments on the GitHub issue %d", n, number), func() bool {
		got = got[:0]
		for _, c := range o.GitHub.IssueComments(owner, repo, number) {
			got = append(got, c.Body)
		}
		return len(got) >= n
	})
	return got
}

// JiraAutomation sends a Jira Automation "Send web request" call.
func (o *Ochell) JiraAutomation(key, summary string) Response {
	o.t.Helper()
	body, err := json.Marshal(map[string]string{
		"issueKey": key, "summary": summary,
		"url":               "https://example.atlassian.net/browse/" + key,
		"assigneeAccountId": BotAccountID, "event": "assigned",
		"initiatorAccountId": o.actor(),
		"labels":             strings.Join(o.Labels, ", "),
		"issueType":          o.IssueType,
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.JiraAutomation.Path, body, map[string]string{
		"Authorization": "Bearer " + AutomationToken,
	})
}

// LinearCreated sends a signed Linear AgentSessionEvent "created": the issue
// was delegated to the agent in a new session.
func (o *Ochell) LinearCreated(key, sessionID, promptContext string) Response {
	o.t.Helper()
	return o.linearCreated(key, sessionID, promptContext, "")
}

// LinearMentioned sends the same event for a session that a comment
// started: someone mentioned the agent on the issue.
func (o *Ochell) LinearMentioned(key, sessionID, comment string) Response {
	o.t.Helper()
	return o.linearCreated(key, sessionID, "", comment)
}

func (o *Ochell) linearCreated(key, sessionID, promptContext, comment string) Response {
	o.t.Helper()
	session := map[string]any{
		"id":      sessionID,
		"creator": map[string]string{"id": o.actor(), "email": "human@example.com"},
		"issue": map[string]any{
			"id": "issue-" + key, "identifier": key, "title": "Title of " + key,
			"url":    "https://linear.app/example/issue/" + key,
			"labels": linearLabels(o.Labels),
		},
	}
	if comment != "" {
		session["comment"] = map[string]string{"id": "comment-" + sessionID, "body": comment}
	}
	body, err := json.Marshal(map[string]any{
		"type": "AgentSessionEvent", "action": "created",
		"organizationId":   "org-0000",
		"agentSession":     session,
		"promptContext":    promptContext,
		"webhookTimestamp": time.Now().UnixMilli(),
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.Linear.Path, body, map[string]string{
		"Linear-Signature": auth.SignHex(LinearSecret, body),
		"Linear-Delivery":  nextDelivery(),
	})
}

// linearLabels is how a Linear payload lists the labels of an issue.
func linearLabels(names []string) []map[string]string {
	out := []map[string]string{}
	for _, n := range names {
		out = append(out, map[string]string{"name": n})
	}
	return out
}

// LinearPrompted sends a signed Linear AgentSessionEvent "prompted": a
// person wrote to the agent in a session that exists.
func (o *Ochell) LinearPrompted(key, sessionID, text string) Response {
	o.t.Helper()
	return o.linearPrompted(key, sessionID, text, "")
}

// LinearStop sends the same event with the stop signal: the person asks
// the agent to stop.
func (o *Ochell) LinearStop(key, sessionID string) Response {
	o.t.Helper()
	return o.linearPrompted(key, sessionID, "", "stop")
}

func (o *Ochell) linearPrompted(key, sessionID, text, signal string) Response {
	o.t.Helper()
	activity := map[string]any{
		"id":      "activity-" + nextDelivery(),
		"content": map[string]string{"type": "prompt", "body": text},
		"user":    map[string]string{"id": o.actor(), "email": "human@example.com"},
	}
	if signal != "" {
		activity["signal"] = signal
	}
	body, err := json.Marshal(map[string]any{
		"type": "AgentSessionEvent", "action": "prompted",
		"organizationId": "org-0000",
		"appUserId":      LinearAppUserID,
		"agentSession": map[string]any{
			"id":      sessionID,
			"creator": map[string]string{"id": o.actor(), "email": "human@example.com"},
			"issue": map[string]string{
				"id": "issue-" + key, "identifier": key, "title": "Title of " + key,
				"url": "https://linear.app/example/issue/" + key,
			},
		},
		"agentActivity":    activity,
		"webhookTimestamp": time.Now().UnixMilli(),
	})
	if err != nil {
		o.t.Fatal(err)
	}
	return o.Post(o.Config.Sources.Linear.Path, body, map[string]string{
		"Linear-Signature": auth.SignHex(LinearSecret, body),
		"Linear-Delivery":  nextDelivery(),
	})
}

// Records returns what the fake agent recorded, one entry per run so far.
func (o *Ochell) Records() []Record {
	o.t.Helper()
	files, _ := filepath.Glob(filepath.Join(o.recordDir, "run-*.json"))
	var recs []Record
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			o.t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal(raw, &r); err != nil {
			o.t.Fatalf("%s: %v", f, err)
		}
		recs = append(recs, r)
	}
	return recs
}

// WaitRecords waits until the fake agent has been started n times.
func (o *Ochell) WaitRecords(n int, timeout time.Duration) []Record {
	o.t.Helper()
	var recs []Record
	o.waitFor(timeout, fmt.Sprintf("%d agent run(s) to start", n), func() bool {
		recs = o.Records()
		return len(recs) >= n
	})
	return recs
}

// Run is the outcome of one agent run, read from its log file.
type Run struct {
	TaskID   string
	ExitCode int
	// Footer is the last line of the log, which ochell writes when the run
	// ends: exit code, error and duration.
	Footer string
	// Log is the whole log file: header, prompt and agent output.
	Log string
}

var footer = regexp.MustCompile(`(?m)^# ---- exit=(-?\d+) .*----$`)

// LogFile returns the path of a task's log file.
func (o *Ochell) LogFile(taskID string) string {
	return filepath.Join(o.Config.Agent.LogDir, taskID+".log")
}

// WaitRun waits until the run of taskID has ended and returns its outcome.
func (o *Ochell) WaitRun(taskID string, timeout time.Duration) Run {
	o.t.Helper()
	run := Run{TaskID: taskID}
	o.waitFor(timeout, "the run of "+taskID+" to end", func() bool {
		raw, err := os.ReadFile(o.LogFile(taskID))
		if err != nil {
			return false
		}
		m := footer.FindStringSubmatch(string(raw))
		if m == nil {
			return false
		}
		run.Log, run.Footer = string(raw), m[0]
		run.ExitCode, _ = strconv.Atoi(m[1])
		return true
	})
	return run
}

// WaitStored waits until ochell has recorded the end of a run in its store,
// and returns the stored run. The log footer that WaitRun looks for is
// written a moment earlier, so a test that reads the store must wait here.
func (o *Ochell) WaitStored(st *store.Store, taskID string, timeout time.Duration) *store.Run {
	o.t.Helper()
	var run *store.Run
	o.waitFor(timeout, "the end of "+taskID+" to be stored", func() bool {
		var err error
		if run, err = st.Run(taskID); err != nil {
			o.t.Fatal(err)
		}
		return run != nil && run.Status == "ended"
	})
	return run
}

// Output returns what ochell has written to stdout and stderr so far.
func (o *Ochell) Output() string { return o.out.String() }

// Signal sends sig to the ochell process.
func (o *Ochell) Signal(sig syscall.Signal) {
	o.t.Helper()
	if err := o.cmd.Process.Signal(sig); err != nil {
		o.t.Fatal(err)
	}
}

// WaitExit waits for the ochell process to exit and returns its exit code.
func (o *Ochell) WaitExit(timeout time.Duration) int {
	o.t.Helper()
	select {
	case <-o.exited:
		return o.cmd.ProcessState.ExitCode()
	case <-time.After(timeout):
		o.t.Fatalf("ochell did not exit within %s", timeout)
		return -1
	}
}

// Alive reports whether a process exists and is not a zombie.
func Alive(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	// A killed process whose parent has not collected it still answers
	// signal 0. On Linux, /proc tells them apart.
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	if i := bytes.LastIndexByte(raw, ')'); i >= 0 && i+2 < len(raw) {
		return raw[i+2] != 'Z'
	}
	return true
}

// Activity is one agent activity posted to the fake Linear API.
type Activity = lineartest.Activity

// FakeLinear is the fake Linear API: it records the activities ochell
// posts, and holds the issues that ochell finds when it asks.
type FakeLinear = lineartest.Server

// WaitActivities waits until a session has received n activities.
func (o *Ochell) WaitActivities(sessionID string, n int, timeout time.Duration) []Activity {
	o.t.Helper()
	var acts []Activity
	o.waitFor(timeout, fmt.Sprintf("%d Linear activities on %s", n, sessionID), func() bool {
		acts = o.Linear.Activities(sessionID)
		return len(acts) >= n
	})
	return acts
}

// WaitJiraComments waits until a ticket of the fake Jira site has n
// comments, and returns them.
func (o *Ochell) WaitJiraComments(key string, n int, timeout time.Duration) []string {
	o.t.Helper()
	var got []string
	o.waitFor(timeout, fmt.Sprintf("%d Jira comments on %s", n, key), func() bool {
		got = o.Jira.Comments(key)
		return len(got) >= n
	})
	return got
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
