//go:build unix

// Command fakeagent stands in for the agent CLI in end-to-end tests.
//
// It records how it was started (arguments, environment, stdin, working
// directory) in $FAKEAGENT_RECORD_DIR and then plays the steps of the JSON
// script in $FAKEAGENT_SCRIPT. Without a script it prints one line and exits
// with status 0.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// Script is what a test asks the fake agent to do.
type Script struct {
	Steps []Step `json:"steps"`
}

// Step does exactly one thing; set one field.
type Step struct {
	// Print writes a line to stdout, Eprint to stderr.
	Print  string `json:"print,omitempty"`
	Eprint string `json:"eprint,omitempty"`
	// Sleep is a Go duration, e.g. "500ms".
	Sleep string `json:"sleep,omitempty"`
	// Spawn starts long-running child processes, as sub-agents and MCP
	// servers are in a real run.
	Spawn *Spawn `json:"spawn,omitempty"`
	// IgnoreTerm makes the agent survive SIGTERM from here on.
	IgnoreTerm bool `json:"ignore_term,omitempty"`
	// Exit ends the run with this status.
	Exit *int `json:"exit,omitempty"`
}

type Spawn struct {
	Count int `json:"count"`
	// Setsid puts the children in a new session, so they leave the agent's
	// process group.
	Setsid bool `json:"setsid,omitempty"`
	// IgnoreTerm makes the children survive SIGTERM.
	IgnoreTerm bool `json:"ignore_term,omitempty"`
}

// Record is written once per run, before the first step.
type Record struct {
	PID   int      `json:"pid"`
	Args  []string `json:"args"`
	Env   []string `json:"env"`
	Stdin string   `json:"stdin"`
	Dir   string   `json:"dir"`
	// Children holds the pids started by spawn steps. The record file is
	// rewritten after each spawn step.
	Children []int `json:"children,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--fakeagent-child" {
		child(len(os.Args) > 2 && os.Args[2] == "ignore-term")
		return
	}
	stdin, _ := io.ReadAll(os.Stdin)
	dir, _ := os.Getwd()
	rec := Record{PID: os.Getpid(), Args: os.Args[1:], Env: os.Environ(), Stdin: string(stdin), Dir: dir}
	writeRecord(rec)

	var script Script
	if p := os.Getenv("FAKEAGENT_SCRIPT"); p != "" {
		raw, err := os.ReadFile(p)
		if err == nil {
			err = json.Unmarshal(raw, &script)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "fakeagent: script:", err)
			os.Exit(64)
		}
	} else {
		script.Steps = []Step{{Print: "fake agent finished " + os.Getenv("ORCH_TASK_KEY")}}
	}

	for _, st := range script.Steps {
		switch {
		case st.Print != "":
			fmt.Println(st.Print)
		case st.Eprint != "":
			fmt.Fprintln(os.Stderr, st.Eprint)
		case st.Sleep != "":
			d, err := time.ParseDuration(st.Sleep)
			if err != nil {
				fmt.Fprintln(os.Stderr, "fakeagent: sleep:", err)
				os.Exit(64)
			}
			time.Sleep(d)
		case st.Spawn != nil:
			for range st.Spawn.Count {
				rec.Children = append(rec.Children, spawn(*st.Spawn))
			}
			writeRecord(rec)
		case st.IgnoreTerm:
			signal.Ignore(syscall.SIGTERM)
		case st.Exit != nil:
			os.Exit(*st.Exit)
		}
	}
}

func spawn(s Spawn) int {
	args := []string{"--fakeagent-child"}
	if s.IgnoreTerm {
		args = append(args, "ignore-term")
	}
	cmd := exec.Command(os.Args[0], args...)
	// The children keep the agent's stdout open, as real children do.
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: s.Setsid}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "fakeagent: spawn:", err)
		os.Exit(64)
	}
	return cmd.Process.Pid
}

func child(ignoreTerm bool) {
	if ignoreTerm {
		signal.Ignore(syscall.SIGTERM)
	}
	time.Sleep(time.Hour)
}

func writeRecord(rec Record) {
	dir := os.Getenv("FAKEAGENT_RECORD_DIR")
	if dir == "" {
		return
	}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	name := filepath.Join(dir, fmt.Sprintf("run-%d.json", rec.PID))
	// Write then rename, so a reader never sees half a record.
	if err := os.WriteFile(name+".tmp", raw, 0o644); err == nil {
		err = os.Rename(name+".tmp", name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fakeagent: record:", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "fakeagent: record:", err)
	}
}
