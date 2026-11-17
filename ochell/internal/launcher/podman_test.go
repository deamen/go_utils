//go:build unix

package launcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ochell/internal/config"
)

// podmanEnv is a podman launcher whose podman is the stand-in.
type podmanEnv struct {
	t     *testing.T
	root  string // for working, run and state directories
	state string // where the stand-in keeps its records
	p     *Podman
}

func newPodmanEnv(t *testing.T) *podmanEnv {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &podmanEnv{t: t, root: filepath.Join(dir, "work"), state: filepath.Join(dir, "podman")}
	for _, d := range []string{e.root, e.state} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake, err := filepath.Abs("testdata/fake-podman")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_PODMAN_DIR", e.state)
	e.p = &Podman{Command: fake, Image: "localhost/agent:1", Pull: "never", StopGrace: 2 * time.Second}
	return e
}

// runArgs returns what the stand-in was called with for a run.
func (e *podmanEnv) runArgs(taskID string) []string {
	e.t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.state, containerPrefix+taskID+".args"))
	if err != nil {
		e.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// The command line of "podman run": the container gets the directories of
// its run and nothing else of the host, and no secret is an argument.
func TestPodmanRunArguments(t *testing.T) {
	p := &Podman{
		Command: "podman", Image: "registry.example.com/agent:7", Pull: "never",
		EnvFile: "/etc/ochell/agent.env", Args: []string{"--memory=4g"},
		Protected: []string{"/var/lib/ochell/logs", "/var/lib/ochell/runs", "/var/lib/ochell/state"},
	}
	spec := Spec{
		TaskID:  "T-1",
		Command: "claude",
		Args:    []string{"-p", "${HOME} $(id)"},
		Dir:     "/work/jira/DEV-1",
		RunDir:  "/var/lib/ochell/runs/T-1",
		Home:    "/var/lib/ochell/state/jira-DEV-1",
		Env:     []string{"ORCH_TASK_KEY=DEV-1", "ORCH_RESULT_FILE=/var/lib/ochell/runs/T-1/result.json"},
		// Only for the direct launcher.
		Inherited: []string{"PATH=/host/bin"},
		Stdin:     strings.NewReader("prompt"),
		Timeout:   time.Hour,
	}
	got, err := p.runArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"run", "--rm", "--name=ochell-run-T-1", "--pull=never", "--log-driver=none",
		"--userns=keep-id", "--cap-drop=all", "--security-opt=no-new-privileges",
		"--env-host=false", "--http-proxy=false",
		"--timeout=3660", "--interactive",
		"--volume=/work/jira/DEV-1:/work/jira/DEV-1:Z",
		"--volume=/var/lib/ochell/runs/T-1:/var/lib/ochell/runs/T-1:Z",
		"--workdir=/work/jira/DEV-1",
		"--volume=/var/lib/ochell/state/jira-DEV-1:/home/agent:Z", "--env=HOME=/home/agent",
		"--env-file=/etc/ochell/agent.env",
		"--env=ORCH_TASK_KEY=DEV-1", "--env=ORCH_RESULT_FILE=/var/lib/ochell/runs/T-1/result.json",
		"--memory=4g",
		"registry.example.com/agent:7", "claude", "-p", "${HOME} $(id)",
	}
	if !slices.Equal(got, want) {
		t.Errorf("podman arguments:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, a := range got {
		if strings.Contains(a, "/host/bin") {
			t.Errorf("argument %q holds a variable of ochell's own", a)
		}
	}
	// Exactly these paths of the host are in the container.
	var mounted []string
	for _, a := range got {
		if v, ok := strings.CutPrefix(a, "--volume="); ok {
			mounted = append(mounted, strings.SplitN(v, ":", 2)[0])
		}
	}
	if want := []string{spec.Dir, spec.RunDir, spec.Home}; !slices.Equal(mounted, want) {
		t.Errorf("mounted %v, want %v", mounted, want)
	}

	// Without a time limit, stdin, run directory and home.
	got, err = p.runArgs(Spec{TaskID: "T-2", Command: "git", Dir: "/work/jira/DEV-1"})
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(got, " "); strings.Contains(s, "--timeout") || strings.Contains(s, "--interactive") || strings.Count(s, "--volume=") != 1 || strings.Count(s, "--env-file=") != 1 {
		t.Errorf("podman arguments of a bare run: %s", s)
	}
}

// A directory that holds files of ochell's own is not mounted, and neither
// is a path that the mount option cannot carry.
func TestPodmanRefusesMounts(t *testing.T) {
	p := &Podman{Command: "podman", Image: "agent", Pull: "never", Protected: []string{"/var/lib/ochell/logs", "/var/lib/ochell/runs"}}
	ok := Spec{TaskID: "T", Command: "true", Dir: "/work/jira/DEV-1", RunDir: "/var/lib/ochell/runs/T", Home: "/var/lib/ochell/state/jira-DEV-1"}
	if _, err := p.runArgs(ok); err != nil {
		t.Fatalf("valid mounts: %v", err)
	}
	cases := map[string]func(s *Spec){
		"the directory of the logs":        func(s *Spec) { s.Dir = "/var/lib/ochell/logs" },
		"a directory above ochell's files": func(s *Spec) { s.Dir = "/var/lib/ochell" },
		"the same, not cleaned":            func(s *Spec) { s.Dir = "/var/lib/ochell/state/.." },
		"the root":                         func(s *Spec) { s.Dir = "/" },
		"all run directories":              func(s *Spec) { s.RunDir = "/var/lib/ochell/runs" },
		"a home above ochell's files":      func(s *Spec) { s.Home = "/var/lib" },
		"a relative working directory":     func(s *Spec) { s.Dir = "work/DEV-1" },
		"a colon in the path":              func(s *Spec) { s.Dir = "/work/a:/etc" },
		"a colon in the run directory":     func(s *Spec) { s.RunDir = "/var/lib/ochell/runs/T:x" },
	}
	for name, change := range cases {
		spec := ok
		change(&spec)
		if _, err := p.runArgs(spec); err == nil {
			t.Errorf("%s: mounted", name)
		}
	}
	// Start reports it as a run that never started, and creates nothing.
	p.Command = "/nonexistent/podman"
	dir := filepath.Join(t.TempDir(), "a:b")
	if _, err := p.Start(Spec{TaskID: "T", Command: "true", Dir: dir}); !errors.Is(err, ErrNotStarted) || !strings.Contains(err.Error(), "mount") {
		t.Errorf("Start with a path that cannot be mounted: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the directory that was refused was created: %v", err)
	}
}

func TestPodmanLauncherRunsAgent(t *testing.T) {
	e := newPodmanEnv(t)
	envFile := filepath.Join(e.state, "agent.env")
	if err := os.WriteFile(envFile, []byte("AGENT_TOKEN=from-the-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.p.EnvFile = envFile
	out := &syncBuffer{}
	dir, runDir, home := filepath.Join(e.root, "jira", "DEV-1"), filepath.Join(e.root, "runs", "T-1"), filepath.Join(e.root, "state", "jira-DEV-1")
	p, err := e.p.Start(Spec{
		TaskID:  "T-1",
		Command: "/bin/sh",
		Args:    []string{"-c", `cat; echo " dir=$PWD key=$ORCH_TASK_KEY home=$HOME token=$AGENT_TOKEN own=${OCHELL_SECRET:-unset}"; exit 4`},
		Dir:     dir, RunDir: runDir, Home: home,
		Env: []string{"ORCH_TASK_KEY=DEV-1"},
		// Only for the direct launcher: a container does not get ochell's
		// variables.
		Inherited: []string{"OCHELL_SECRET=leak"},
		Stdin:     strings.NewReader("the prompt"),
		Output:    out,
		Timeout:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	code, err := p.Wait()
	if code != 4 || err != nil {
		t.Errorf("Wait = %d, %v; want the agent's exit code 4", code, err)
	}
	want := "the prompt dir=" + dir + " key=DEV-1 home=" + home + " token=from-the-file own=unset\n"
	if got := out.String(); got != want {
		t.Errorf("output %q, want %q", got, want)
	}
	for _, d := range []string{dir, runDir, home} {
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			t.Errorf("%s was not created: %v", d, err)
		}
	}
	args := e.runArgs("T-1")
	if slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "from-the-file") }) {
		t.Errorf("a secret is on podman's command line:\n%s", strings.Join(args, "\n"))
	}
	if !slices.Contains(args, "--env-file="+envFile) {
		t.Errorf("the env file is missing:\n%s", strings.Join(args, "\n"))
	}
}

func TestPodmanLauncherStop(t *testing.T) {
	e := newPodmanEnv(t)
	out := &syncBuffer{}
	p, err := e.p.Start(Spec{TaskID: "T-stop", Command: "/bin/sh", Args: []string{"-c", "echo started; exec sleep 600"}, Dir: e.root, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		_, err := p.Wait()
		waited <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(out.String(), "started"); {
		if time.Now().After(deadline) {
			t.Fatal("agent did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-waited:
		if err != nil {
			t.Errorf("Wait after a stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not end after Stop")
	}
	calls, _ := os.ReadFile(filepath.Join(e.state, "calls"))
	if got, want := string(calls), "stop --ignore --time=2 ochell-run-T-stop\n"; got != want {
		t.Errorf("podman was called with %q, want %q", got, want)
	}
}

// After a crash of ochell the container of a run is still there. The next
// ochell knows only the task id, and removes the container by its name.
func TestPodmanLauncherReap(t *testing.T) {
	e := newPodmanEnv(t)
	out := &syncBuffer{}
	p, err := e.p.Start(Spec{TaskID: "T-left", Command: "/bin/sh", Args: []string{"-c", "echo started; exec sleep 600"}, Dir: e.root, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		_, err := p.Wait()
		waited <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(out.String(), "started"); {
		if time.Now().After(deadline) {
			t.Fatal("agent did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A launcher that did not start the run, as after a restart.
	again := *e.p
	if err := again.Reap("T-left"); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not end after Reap")
	}
	// Nothing left of a run is not an error.
	if err := again.Reap("T-never-ran"); err != nil {
		t.Errorf("Reap of a run that left nothing: %v", err)
	}
	calls, _ := os.ReadFile(filepath.Join(e.state, "calls"))
	if got, want := string(calls), "rm --force --ignore --time=2 ochell-run-T-left\nrm --force --ignore --time=2 ochell-run-T-never-ran\n"; got != want {
		t.Errorf("podman was called with %q, want %q", got, want)
	}
}

// A container that podman could not create, or a command that the image
// does not have, is not an agent failure.
func TestPodmanLauncherNotStarted(t *testing.T) {
	e := newPodmanEnv(t)
	t.Setenv("FAKE_PODMAN_REFUSE", "1")
	out := &syncBuffer{}
	p, err := e.p.Start(Spec{TaskID: "T-refused", Command: "/bin/true", Dir: e.root, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	if code, err := p.Wait(); code != 125 || !errors.Is(err, ErrNotStarted) {
		t.Errorf("Wait = %d, %v; want 125 and ErrNotStarted", code, err)
	}
	if !strings.Contains(out.String(), "image not known") {
		t.Errorf("podman's reason is not in the run output: %q", out.String())
	}

	for _, code := range []int{126, 127} {
		script := filepath.Join(e.state, fmt.Sprintf("podman-%d", code))
		if err := os.WriteFile(script, fmt.Appendf(nil, "#!/bin/sh\nexit %d\n", code), 0o755); err != nil {
			t.Fatal(err)
		}
		q := &Podman{Command: script, Image: "agent", Pull: "never"}
		p, err := q.Start(Spec{TaskID: "T-code", Command: "/bin/true", Dir: e.root, Output: out})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := p.Wait(); got != code || !errors.Is(err, ErrNotStarted) {
			t.Errorf("Wait = %d, %v; want %d and ErrNotStarted", got, err, code)
		}
	}
	// 124 and 128 are the agent's own.
	script := filepath.Join(e.state, "podman-124")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 124\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err = (&Podman{Command: script, Image: "agent", Pull: "never"}).Start(Spec{TaskID: "T-124", Command: "/bin/true", Dir: e.root, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Wait(); got != 124 || err != nil {
		t.Errorf("Wait = %d, %v; want the agent's exit code 124", got, err)
	}

	e.p.Command = "/nonexistent/podman"
	if _, err := e.p.Start(Spec{TaskID: "T-none", Command: "/bin/true", Dir: e.root, Output: out}); !errors.Is(err, ErrNotStarted) {
		t.Errorf("missing podman: %v, want ErrNotStarted", err)
	}
}

// New makes the paths of the podman launcher absolute, and refuses a
// credential file that others can read.
func TestNewPodman(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envFile, []byte("TOKEN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Agent
	cfg.Launcher = "podman"
	cfg.Podman.Image = "agent"
	cfg.Podman.EnvFile = envFile
	cfg.Podman.Args = []string{"--memory=1g"}
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := l.(*Podman)
	if !ok {
		t.Fatalf("New returned %T", l)
	}
	if p.Command != "podman" || p.Pull != "never" || p.EnvFile != envFile || len(p.Args) != 1 {
		t.Errorf("launcher = %+v", p)
	}
	if len(p.Protected) != 3 || slices.ContainsFunc(p.Protected, func(d string) bool { return !filepath.IsAbs(d) }) {
		t.Errorf("protected directories = %v", p.Protected)
	}

	if err := os.Chmod(envFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "agent.podman.env_file") {
		t.Errorf("a credential file that the group can read: %v", err)
	}
	cfg.Podman.EnvFile = filepath.Join(dir, "missing.env")
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "agent.podman.env_file") {
		t.Errorf("a missing credential file: %v", err)
	}
}
