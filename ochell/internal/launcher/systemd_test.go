//go:build unix

package launcher

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (e *scriptEnv) launcher() *Systemd {
	return &Systemd{LaunchCommand: e.launch, StopCommand: e.stop, StopGrace: 2 * time.Second}
}

// The systemd launcher and the real scripts, with systemd itself replaced by
// the stand-ins. The real thing is checked on the VM.
func TestSystemdLauncherRunsAgent(t *testing.T) {
	e := newScriptEnv(t)
	out := &syncBuffer{}
	dir := filepath.Join(e.root, "jira", "DEV-1")
	p, err := e.launcher().Start(Spec{
		TaskID:  "T-1",
		Command: "/bin/sh",
		Args:    []string{"-c", `cat; echo " key=$ORCH_TASK_KEY home=${HOME:-unset} secret=${OCHELL_SECRET:-unset}"; exit 4`},
		Dir:     dir,
		Env:     []string{"ORCH_TASK_KEY=DEV-1"},
		// Only for the direct launcher: a unit does not get ochell's variables.
		Inherited: []string{"HOME=/home/ochell", "OCHELL_SECRET=leak"},
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
	if got, want := out.String(), "the prompt key=DEV-1 home=unset secret=unset\n"; got != want {
		t.Errorf("output %q, want %q", got, want)
	}
	args := strings.Join(e.unitArgs("T-1"), "\n")
	// The unit's own limit is a backstop, a minute after ochell's timer.
	for _, want := range []string{"RuntimeMaxSec=3660", "TimeoutStopSec=2", "--working-directory=" + dir} {
		if !strings.Contains(args, want) {
			t.Errorf("unit options missing %s:\n%s", want, args)
		}
	}
}

func TestSystemdLauncherStop(t *testing.T) {
	e := newScriptEnv(t)
	out := &syncBuffer{}
	p, err := e.launcher().Start(Spec{TaskID: "T-stop", Command: "/bin/sh", Args: []string{"-c", "echo started; exec sleep 600"}, Dir: e.root, Output: out})
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
}

// After a crash of ochell the unit of a run is still there. The next ochell
// knows only the task id, and stops the unit by it.
func TestSystemdLauncherReap(t *testing.T) {
	e := newScriptEnv(t)
	out := &syncBuffer{}
	p, err := e.launcher().Start(Spec{TaskID: "T-left", Command: "/bin/sh", Args: []string{"-c", "echo started; exec sleep 600"}, Dir: e.root, Output: out})
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
	if err := e.launcher().Reap("T-left"); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not end after Reap")
	}
	// Nothing left of a run is not an error.
	if err := e.launcher().Reap("T-never-ran"); err != nil {
		t.Errorf("Reap of a run that left nothing: %v", err)
	}
	if err := (Direct{}).Reap("T-left"); err != nil {
		t.Errorf("Direct.Reap: %v", err)
	}
}

// A refused launch (250) or a unit that systemd could not start (200-243)
// is not an agent failure.
func TestSystemdLauncherNotStarted(t *testing.T) {
	e := newScriptEnv(t)
	out := &syncBuffer{}
	p, err := e.launcher().Start(Spec{TaskID: "T-out", Command: "/bin/true", Dir: "/somewhere/else", Output: out})
	if err != nil {
		t.Fatal(err)
	}
	code, err := p.Wait()
	if code != 250 || !errors.Is(err, ErrNotStarted) {
		t.Errorf("Wait = %d, %v; want 250 and ErrNotStarted", code, err)
	}
	if !strings.Contains(out.String(), "ochell-launch: the working directory is outside") {
		t.Errorf("the reason is not in the run output: %q", out.String())
	}

	s := &Systemd{LaunchCommand: []string{"/bin/sh", "-c", "exit 203", "launch"}, StopCommand: []string{"/bin/true"}}
	p, err = s.Start(Spec{TaskID: "T-203", Command: "/bin/true", Dir: e.root, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	if code, err := p.Wait(); code != 203 || !errors.Is(err, ErrNotStarted) {
		t.Errorf("Wait = %d, %v; want 203 and ErrNotStarted", code, err)
	}

	s = &Systemd{LaunchCommand: []string{"/nonexistent/ochell-launch"}, StopCommand: []string{"/bin/true"}}
	if _, err := s.Start(Spec{TaskID: "T-none", Command: "/bin/true", Dir: e.root, Output: out}); !errors.Is(err, ErrNotStarted) {
		t.Errorf("missing launch command: %v, want ErrNotStarted", err)
	}
}

func TestDirectLauncher(t *testing.T) {
	out := &syncBuffer{}
	dir := filepath.Join(t.TempDir(), "new", "dir")
	p, err := Direct{}.Start(Spec{
		Command: "/bin/sh", Args: []string{"-c", `pwd; cat; echo " a=$A b=$B"; exit 5`}, Dir: dir,
		Env: []string{"A=1"}, Inherited: []string{"B=2"}, Stdin: strings.NewReader("in"), Output: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, err := p.Wait(); code != 5 || err != nil {
		t.Errorf("Wait = %d, %v", code, err)
	}
	if got, want := out.String(), dir+"\nin a=1 b=2\n"; got != want {
		t.Errorf("output %q, want %q", got, want)
	}
	if _, err := (Direct{}).Start(Spec{Command: "/nonexistent/agent", Dir: dir, Output: out}); !errors.Is(err, ErrNotStarted) {
		t.Errorf("missing command: %v, want ErrNotStarted", err)
	}
}
