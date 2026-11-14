package result

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	f, err := Parse([]byte(`{"status":"done","message":" Opened PR #7. ","pr_url":"https://github.com/x/y/pull/7","branch":"bot/ENG-1","notes":"extra"}`))
	if err != nil {
		t.Fatal(err)
	}
	if *f != (File{Status: Done, Message: "Opened PR #7.", PRURL: "https://github.com/x/y/pull/7", Branch: "bot/ENG-1"}) {
		t.Errorf("parsed %+v", f)
	}
	if f, err := Parse([]byte(`{"status":"done"}`)); err != nil || f.Status != Done {
		t.Errorf("done needs no message: %v, %v", f, err)
	}
	for _, s := range []Status{NeedsInput, Blocked, LowConfidence, OutOfScope} {
		if f, err := Parse([]byte(`{"status":"` + string(s) + `","message":"why"}`)); err != nil || f.Status != s {
			t.Errorf("%s: %v, %v", s, f, err)
		}
		if _, err := Parse([]byte(`{"status":"` + string(s) + `","message":"  "}`)); err == nil {
			t.Errorf("%s without a message must be refused", s)
		}
	}
	for name, raw := range map[string]string{
		"empty":            ``,
		"not json":         `done`,
		"an array":         `["done"]`,
		"no status":        `{"message":"hi"}`,
		"unknown status":   `{"status":"finished"}`,
		"status not text":  `{"status":1}`,
		"message not text": `{"status":"done","message":{"a":1}}`,
		"url with newline": `{"status":"done","pr_url":"https://x\nINJECTED"}`,
		"huge branch":      `{"status":"done","branch":"` + strings.Repeat("b", 3000) + `"}`,
	} {
		if f, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: accepted as %+v", name, f)
		}
	}
}

// The prompt names what Parse accepts.
func TestInstructionsNameEveryStatus(t *testing.T) {
	for _, s := range []Status{Done, NeedsInput, Blocked, LowConfidence, OutOfScope} {
		if !strings.Contains(Instructions, "  "+string(s)+" ") {
			t.Errorf("the instructions do not explain %q", s)
		}
	}
	for _, want := range []string{EnvVar, `"status"`, `"message"`, `"pr_url"`, `"branch"`} {
		if !strings.Contains(Instructions, want) {
			t.Errorf("the instructions do not mention %s", want)
		}
	}
}

func TestRead(t *testing.T) {
	runs := t.TempDir()
	write := func(run, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(runs, run), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runs, run, FileName), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("ok", `{"status":"needs_input","message":"Which branch?"}`)
	if f, err := Read(runs, "ok"); err != nil || f.Status != NeedsInput || f.Message != "Which branch?" {
		t.Errorf("Read = %+v, %v", f, err)
	}

	if _, err := Read(runs, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a run without a file: %v, want not exist", err)
	}
	write("bad", `{"status":"maybe"}`)
	if _, err := Read(runs, "bad"); err == nil || !strings.Contains(err.Error(), "unknown status") {
		t.Errorf("invalid file: %v", err)
	}
	write("huge", `{"status":"done","message":"`+strings.Repeat("x", maxSize)+`"}`)
	if _, err := Read(runs, "huge"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: %v", err)
	}

	// The agent owns these directories. A link must not make ochell read a
	// file of its own, which the agent cannot read itself.
	secret := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(secret, []byte(`{"status":"done","message":"ochell's secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(runs, "link-file"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(runs, "link-file", FileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(secret), filepath.Join(runs, "link-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(secret, filepath.Join(filepath.Dir(secret), FileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(secret), FileName), filepath.Join(runs, "link-file", "x")); err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{"link-file", "link-dir", "../" + filepath.Base(filepath.Dir(secret))} {
		if f, err := Read(runs, run); err == nil {
			t.Errorf("Read(%q) followed a path out of the run directory: %+v", run, f)
		}
	}
	// A directory where the file should be.
	if err := os.MkdirAll(filepath.Join(runs, "dir", FileName), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(runs, "dir"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory as the result file: %v", err)
	}
}
