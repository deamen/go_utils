//go:build unix

package launcher

import (
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// scriptEnv is a workspace and settings file for the launch and stop
// scripts, with systemd replaced by the stand-ins in testdata. The scripts
// accept these overrides only when they do not run as root.
type scriptEnv struct {
	t         *testing.T
	root      string // workspace root
	systemd   string // where the stand-ins keep their records
	launch    []string
	stop      []string
	agentUser string
}

func abs(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// newScriptEnv writes a settings file; extra lines are appended to it.
func newScriptEnv(t *testing.T, extra ...string) *scriptEnv {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the scripts ignore the test overrides when run as root")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &scriptEnv{t: t, root: filepath.Join(dir, "work"), systemd: filepath.Join(dir, "systemd"), agentUser: u.Username}
	for _, d := range []string{e.root, e.systemd} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	envFile := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envFile, []byte("AGENT_TOKEN=token-from-env-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "launcher.conf")
	lines := append([]string{"AGENT_USER=" + e.agentUser, "WORKSPACE_ROOT=" + e.root, "ENV_FILE=" + envFile}, extra...)
	if err := os.WriteFile(conf, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	overrides := []string{
		"/usr/bin/env",
		"OCHELL_LAUNCHER_CONF=" + conf,
		"OCHELL_LAUNCHER_SYSTEMD_RUN=" + abs(t, "testdata/fake-systemd-run"),
		"OCHELL_LAUNCHER_SYSTEMCTL=" + abs(t, "testdata/fake-systemctl"),
		"FAKE_SYSTEMD_DIR=" + e.systemd,
	}
	e.launch = append(append([]string{}, overrides...), abs(t, "../../scripts/ochell-launch"))
	e.stop = append(append([]string{}, overrides...), abs(t, "../../scripts/ochell-stop"))
	return e
}

type scriptResult struct {
	code   int
	stdout string
	stderr string
}

func run(t *testing.T, stdin string, argv []string, args ...string) scriptResult {
	t.Helper()
	cmd := exec.Command(argv[0], append(append([]string{}, argv[1:]...), args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatal(err)
	}
	return scriptResult{cmd.ProcessState.ExitCode(), out.String(), errb.String()}
}

// unitArgs returns what the launch script passed to systemd-run.
func (e *scriptEnv) unitArgs(task string) []string {
	e.t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.systemd, "ochell-run-"+task+".args"))
	if err != nil {
		e.t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func (e *scriptEnv) started() bool {
	files, _ := filepath.Glob(filepath.Join(e.systemd, "*.args"))
	return len(files) > 0
}

func TestLaunchScriptStartsUnit(t *testing.T) {
	e := newScriptEnv(t)
	dir := filepath.Join(e.root, "jira", "DEV-1")
	res := run(t, "prompt on stdin", e.launch,
		"--task", "T-1.jira_DEV-1", "--workdir", dir, "--runtime-max", "7260", "--stop-grace", "10",
		"--setenv", "ORCH_TASK_KEY=DEV-1", "--setenv", "ORCH_TASK_URL=https://x/${AGENT_TOKEN}",
		"--", "/bin/sh", "-c", `pwd; cat; echo; echo "key=$ORCH_TASK_KEY url=$ORCH_TASK_URL token=$AGENT_TOKEN leak=${OCHELL_LAUNCHER_CONF:-none}"; exit 7`)
	if res.code != 7 {
		t.Fatalf("exit code %d, want the agent's 7; stderr: %s", res.code, res.stderr)
	}
	// Stdin, stdout, the working directory and the environment reach the
	// agent; the value passed with --setenv is not expanded.
	want := dir + "\nprompt on stdin\nkey=DEV-1 url=https://x/${AGENT_TOKEN} token=token-from-env-file leak=none\n"
	if res.stdout != want {
		t.Errorf("agent output:\n%s\nwant:\n%s", res.stdout, want)
	}

	got := e.unitArgs("T-1.jira_DEV-1")
	i := 0
	for ; i < len(got) && got[i] != "--"; i++ {
	}
	opts, cmd := strings.Join(got[:i], "\n")+"\n", got[i:]
	for _, w := range []string{
		"--uid=" + e.agentUser + "\n", "--unit=ochell-run-T-1.jira_DEV-1\n", "--wait\n", "--pipe\n", "--collect\n",
		"--no-ask-password\n", "--working-directory=" + dir + "\n", "KillMode=control-group\n",
		"EnvironmentFile=" + filepath.Join(filepath.Dir(e.root), "agent.env") + "\n",
		"RuntimeMaxSec=7260\n", "TimeoutStopSec=10\n", "--setenv=ORCH_TASK_KEY=DEV-1\n",
	} {
		if !strings.Contains(opts, w) {
			t.Errorf("systemd-run options missing %q:\n%s", w, opts)
		}
	}
	if strings.Contains(opts, "IPAddressDeny") {
		t.Errorf("loopback is denied without DENY_LOOPBACK=1:\n%s", opts)
	}
	// The command comes after "--" and starts through /usr/bin/env.
	if len(cmd) < 3 || cmd[1] != "/usr/bin/env" || cmd[2] != "/bin/sh" {
		t.Errorf("command after the options = %q", cmd)
	}
}

// systemd replaces ${VAR} in arguments from the unit's environment, which
// holds the agent's token. The launch script must escape every "$".
func TestLaunchScriptEscapesDollarInArguments(t *testing.T) {
	e := newScriptEnv(t)
	const arg = `A${AGENT_TOKEN}B $AGENT_TOKEN $$ 100%h`
	res := run(t, "", e.launch, "--task", "T-2", "--workdir", e.root, "--", "/usr/bin/printf", "%s", arg)
	if res.code != 0 || res.stdout != arg {
		t.Errorf("the argument reached the agent as %q (exit %d, stderr %q), want it unchanged: %q", res.stdout, res.code, res.stderr, arg)
	}
	if strings.Contains(strings.Join(e.unitArgs("T-2"), "\n"), "token-from-env-file") {
		t.Error("the token is on the command line")
	}

	// Control: the stand-in does expand an unescaped ${VAR}, as systemd
	// does, so the check above proves something.
	out, err := exec.Command("/usr/bin/env", "FAKE_SYSTEMD_DIR="+e.systemd, abs(t, "testdata/fake-systemd-run"),
		"--unit=control", "-p", "EnvironmentFile="+filepath.Join(filepath.Dir(e.root), "agent.env"),
		"--", "/usr/bin/printf", "%s", "A${AGENT_TOKEN}B").Output()
	if err != nil || string(out) != "Atoken-from-env-fileB" {
		t.Fatalf("stand-in did not expand ${VAR}: %q %v", out, err)
	}
}

func TestLaunchScriptRefuses(t *testing.T) {
	e := newScriptEnv(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(e.root, "link")); err != nil {
		t.Fatal(err)
	}
	ok := []string{"--task", "T-1", "--workdir", filepath.Join(e.root, "a"), "--", "/bin/true"}
	with := func(i int, v string) []string {
		args := append([]string{}, ok...)
		args[i] = v
		return args
	}
	cases := map[string][]string{
		"empty task id":            with(1, ""),
		"task id with a slash":     with(1, "../x"),
		"task id with a space":     with(1, "a b"),
		"task id like an option":   with(1, "-x"),
		"task id with a newline":   with(1, "a\nb"),
		"task id too long":         with(1, strings.Repeat("a", 129)),
		"workdir outside the root": with(3, outside),
		"workdir is the parent":    with(3, filepath.Dir(e.root)),
		"workdir with ..":          with(3, e.root+"/a/../../x"),
		"workdir relative":         with(3, "work/a"),
		"workdir sibling prefix":   with(3, e.root+"-other"),
		"workdir through symlink":  with(3, filepath.Join(e.root, "link", "x")),
		"workdir like an option":   with(3, "--uid=root"),
		"relative command":         with(5, "claude"),
		"option as the command":    with(5, "--uid=root"),
		"command with a space":     with(5, "/bin/true --uid=root"),
		"command with =":           with(5, "/tmp/A=B"),
		"no command":               ok[:5],
		"no --":                    ok[:4],
		"option before --":         append([]string{"--uid=root"}, ok...),
		"property before --":       append([]string{"-p", "User=root"}, ok...),
		"env name not allowed":     append([]string{"--setenv", "LD_PRELOAD=/tmp/x.so"}, ok...),
		"env name with a space":    append([]string{"--setenv", "ORCH_A B=1"}, ok...),
		"env without a value":      append([]string{"--setenv", "ORCH_A"}, ok...),
		"env value with a newline": append([]string{"--setenv", "ORCH_A=1\nUser=root"}, ok...),
		"runtime not a number":     append([]string{"--runtime-max", "1; reboot"}, ok...),
		"grace not a number":       append([]string{"--stop-grace", "-1"}, ok...),
		"missing option value":     {"--task"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			res := run(t, "", e.launch, args...)
			if res.code != 250 {
				t.Errorf("exit code %d, want 250 (refused); stderr: %s", res.code, res.stderr)
			}
			if !strings.HasPrefix(res.stderr, "ochell-launch: ") {
				t.Errorf("no reason on stderr: %q", res.stderr)
			}
		})
	}
	if e.started() {
		t.Error("systemd-run was called for a refused request")
	}
	if _, err := os.Stat(filepath.Join(outside, "x")); err == nil {
		t.Error("a directory was created outside the workspace root")
	}
	// The request the cases are derived from is itself accepted.
	if res := run(t, "", e.launch, ok...); res.code != 0 {
		t.Fatalf("the valid request was refused: %d %s", res.code, res.stderr)
	}
}

func TestLaunchScriptSettings(t *testing.T) {
	t.Run("allowed env and loopback", func(t *testing.T) {
		e := newScriptEnv(t, `ALLOWED_ENV='^(CI|CLAUDE_CONFIG_DIR)$'`, "DENY_LOOPBACK=1")
		res := run(t, "", e.launch, "--task", "T-1", "--workdir", e.root, "--setenv", "CI=true", "--", "/bin/sh", "-c", `echo "ci=$CI"`)
		if res.code != 0 || res.stdout != "ci=true\n" {
			t.Errorf("exit %d stdout %q stderr %q", res.code, res.stdout, res.stderr)
		}
		if !strings.Contains(strings.Join(e.unitArgs("T-1"), "\n"), "IPAddressDeny=localhost") {
			t.Error("DENY_LOOPBACK=1 did not deny loopback")
		}
		if res := run(t, "", e.launch, "--task", "T-2", "--workdir", e.root, "--setenv", "CIX=1", "--", "/bin/true"); res.code != 250 {
			t.Errorf("a name outside ALLOWED_ENV: exit %d", res.code)
		}
	})
	for name, line := range map[string]string{
		"root as the agent user":  "AGENT_USER=root",
		"unknown agent user":      "AGENT_USER=no-such-user-ochell",
		"no agent user":           "AGENT_USER=",
		"relative workspace root": "WORKSPACE_ROOT=work",
		"missing workspace root":  "WORKSPACE_ROOT=/nonexistent/ochell",
		"workspace root is /":     "WORKSPACE_ROOT=/",
		"missing env file":        "ENV_FILE=/nonexistent/agent.env",
	} {
		t.Run(name, func(t *testing.T) {
			e := newScriptEnv(t, line)
			dir := e.root
			if strings.HasPrefix(line, "WORKSPACE_ROOT=/") {
				dir = strings.TrimPrefix(line, "WORKSPACE_ROOT=")
			}
			if res := run(t, "", e.launch, "--task", "T-1", "--workdir", dir, "--", "/bin/true"); res.code != 250 {
				t.Errorf("exit code %d, want 250; stderr: %s", res.code, res.stderr)
			}
			if e.started() {
				t.Error("systemd-run was called with unusable settings")
			}
		})
	}
}

func TestStopScript(t *testing.T) {
	e := newScriptEnv(t)
	calls := func() string {
		raw, _ := os.ReadFile(filepath.Join(e.systemd, "systemctl.calls"))
		return string(raw)
	}
	// A unit that is not running is not an error: the run has ended.
	if res := run(t, "", e.stop, "T-1.x_y"); res.code != 0 {
		t.Errorf("stop of a finished run: exit %d, stderr %s", res.code, res.stderr)
	}
	if got := calls(); got != "stop -- ochell-run-T-1.x_y.service\n" {
		t.Errorf("systemctl called with %q", got)
	}
	for name, args := range map[string][]string{
		"no id":         {},
		"two arguments": {"T-1", "T-2"},
		"option":        {"--all"},
		"glob":          {"*"},
		"other unit":    {"x.service sshd"},
		"path":          {"../sshd"},
	} {
		t.Run(name, func(t *testing.T) {
			if res := run(t, "", e.stop, args...); res.code != 250 {
				t.Errorf("exit code %d, want 250; stderr: %s", res.code, res.stderr)
			}
		})
	}
	if got := calls(); strings.Count(got, "\n") != 1 {
		t.Errorf("systemctl was called for a refused request:\n%s", got)
	}
}
