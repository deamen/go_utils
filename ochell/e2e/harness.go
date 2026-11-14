//go:build unix

// Package e2e is the end-to-end test harness. It starts a real ochell
// process with a scripted fake agent (see fakeagent) and a fake Linear API,
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
	"net/http/httptest"
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
	IgnoreTerm bool   `json:"ignore_term,omitempty"`
	Exit       *int   `json:"exit,omitempty"`
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
	// Env is added to the environment of the ochell process.
	Env []string
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
	o.Linear = newFakeLinear(t)

	port := freePort(t)
	cfg := config.Default()
	cfg.LogLevel = "debug"
	cfg.HTTP = config.Listener{Enabled: true, Address: "127.0.0.1", Port: port}
	cfg.Store.Path = filepath.Join(dir, "ochell.db")
	cfg.Agent.Command = agentBin
	cfg.Agent.Args = nil
	cfg.Agent.PromptVia = "stdin"
	cfg.Agent.Workdir = filepath.Join(dir, "work", "{{.Source}}-{{.Key}}")
	cfg.Agent.LogDir = filepath.Join(dir, "logs")
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
	cfg.Sources.Linear.Enabled = true
	cfg.Sources.Linear.Secret = LinearSecret
	cfg.Sources.Linear.ClientID = "e2e-client-id"
	cfg.Sources.Linear.ClientSecret = "e2e-client-secret"
	cfg.Sources.Linear.TokenFile = filepath.Join(dir, "linear-token.json")
	cfg.Sources.Linear.APIURL = o.Linear.URL
	cfg.Sources.Linear.TokenURL = o.Linear.URL + "/oauth/token"
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
	body, err := json.Marshal(map[string]any{
		"timestamp":             time.Now().UnixMilli(),
		"webhookEvent":          "jira:issue_updated",
		"issue_event_type_name": "issue_assigned",
		"issue": map[string]any{
			"id": "10042", "key": key,
			"self": "https://example.atlassian.net/rest/api/2/issue/10042",
			"fields": map[string]any{
				"summary":  summary,
				"assignee": map[string]string{"accountId": BotAccountID},
			},
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

// JiraAutomation sends a Jira Automation "Send web request" call.
func (o *Ochell) JiraAutomation(key, summary string) Response {
	o.t.Helper()
	body, err := json.Marshal(map[string]string{
		"issueKey": key, "summary": summary,
		"url":               "https://example.atlassian.net/browse/" + key,
		"assigneeAccountId": BotAccountID, "event": "assigned",
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
	body, err := json.Marshal(map[string]any{
		"type": "AgentSessionEvent", "action": "created",
		"organizationId": "org-0000",
		"agentSession": map[string]any{
			"id": sessionID,
			"issue": map[string]string{
				"id": "issue-" + key, "identifier": key, "title": "Title of " + key,
				"url": "https://linear.app/example/issue/" + key,
			},
		},
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
type Activity struct {
	SessionID string
	Type      string
	Body      string
	At        time.Time
}

// FakeLinear records the GraphQL calls ochell makes to Linear.
type FakeLinear struct {
	URL string

	mu         sync.Mutex
	activities []Activity
}

func newFakeLinear(t *testing.T) *FakeLinear {
	f := &FakeLinear{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

func (f *FakeLinear) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+LinearToken {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"errors":[{"message":"authentication failed"}]}`)
		return
	}
	var req struct {
		Variables struct {
			Input struct {
				AgentSessionID string `json:"agentSessionId"`
				Content        struct {
					Type string `json:"type"`
					Body string `json:"body"`
				} `json:"content"`
			} `json:"input"`
		} `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if in := req.Variables.Input; in.Content.Type != "" {
		f.mu.Lock()
		f.activities = append(f.activities, Activity{SessionID: in.AgentSessionID, Type: in.Content.Type, Body: in.Content.Body, At: time.Now()})
		f.mu.Unlock()
	}
	io.WriteString(w, `{"data":{"agentActivityCreate":{"success":true},"agentSessionUpdate":{"success":true}}}`)
}

// Activities returns the activities posted to a session so far.
func (f *FakeLinear) Activities(sessionID string) []Activity {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Activity
	for _, a := range f.activities {
		if a.SessionID == sessionID {
			out = append(out, a)
		}
	}
	return out
}

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
