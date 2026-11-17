//go:build unix

package launcher

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

func TestDirectLauncher(t *testing.T) {
	out := &syncBuffer{}
	dir := filepath.Join(t.TempDir(), "new", "dir")
	p, err := Direct{}.Start(Spec{
		Command: "/bin/sh", Args: []string{"-c", `pwd; cat; echo " a=$A b=$B"; exit 5`}, Dir: dir,
		Env: []string{"A=1", "B=2"}, Stdin: strings.NewReader("in"), Output: out,
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

// alive reports whether the process runs. A killed process that its parent
// has not collected yet still answers signal 0; on Linux, /proc tells them
// apart.
func alive(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	if i := bytes.LastIndexByte(raw, ')'); i >= 0 && i+2 < len(raw) {
		return raw[i+2] != 'Z'
	}
	return true
}

// A stop ends the whole process group of the agent: a child that ignores
// SIGTERM is killed after the grace period, and nothing is left behind.
func TestDirectLauncherStopLeavesNoChildBehind(t *testing.T) {
	out := &syncBuffer{}
	p, err := Direct{StopGrace: 500 * time.Millisecond}.Start(Spec{
		Command: "/bin/sh",
		Args:    []string{"-c", `sh -c 'trap "" TERM; while :; do sleep 1; done' & echo "child $!"; wait`},
		Dir:     t.TempDir(), Output: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	var child int
	deadline := time.Now().Add(10 * time.Second)
	for child == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the agent did not report its child; output %q", out.String())
		}
		if _, rest, ok := strings.Cut(out.String(), "child "); ok {
			child, _ = strconv.Atoi(strings.TrimSpace(rest))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Whatever the result, nothing of the test may outlive it.
	t.Cleanup(func() {
		if alive(child) {
			syscall.Kill(child, syscall.SIGKILL)
		}
	})
	done := make(chan struct{})
	go func() {
		p.Wait()
		close(done)
	}()
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after Stop")
	}
	// The child is killed, not waited for; give the kernel a moment.
	deadline = time.Now().Add(5 * time.Second)
	for alive(child) {
		if time.Now().After(deadline) {
			t.Fatalf("child %d is still running after the stop", child)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
