//go:build unix

// Command fakeagent stands in for the agent CLI in end-to-end tests.
//
// It records how it was started (arguments, environment, stdin, working
// directory) in $FAKEAGENT_RECORD_DIR and then plays the steps of the JSON
// script in $FAKEAGENT_SCRIPT. Without a script it prints one line and exits
// with status 0.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
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
	// WriteFile creates a file; a relative path is in the working
	// directory, and $NAME in the path is replaced from the environment
	// (e.g. $ORCH_RESULT_FILE).
	WriteFile *File `json:"write_file,omitempty"`
	// TryRead reads a file and notes in the record whether that worked.
	TryRead string `json:"try_read,omitempty"`
	// WaitFile waits until a file exists, so that a test decides when the
	// run goes on. $NAME in the path is replaced from the environment
	// (e.g. $ORCH_TASK_KEY).
	WaitFile string `json:"wait_file,omitempty"`
	// IgnoreTerm makes the agent survive SIGTERM from here on.
	IgnoreTerm bool `json:"ignore_term,omitempty"`
	// MCP sends one request to the MCP server "ochell" of the run's MCP
	// configuration, as an agent CLI does, and notes the answer in the
	// record.
	MCP *MCP `json:"mcp,omitempty"`
	// Exit ends the run with this status.
	Exit *int `json:"exit,omitempty"`
	// OnRun limits the step to one run of the fake agent: 1 is the first
	// run that left a record in $FAKEAGENT_RECORD_DIR, 2 the second, and
	// so on. 0: every run.
	OnRun int `json:"on_run,omitempty"`
}

type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// MCP is one request to ochell's MCP server.
type MCP struct {
	// Method is the method of the protocol, such as "tools/list". With
	// Tool set it is "tools/call" for that tool, with Args.
	Method string         `json:"method,omitempty"`
	Tool   string         `json:"tool,omitempty"`
	Args   map[string]any `json:"args,omitempty"`
	// TokenFile, when set, holds the token to send in the place of the
	// run's own. $NAME in the path is replaced from the environment.
	TokenFile string `json:"token_file,omitempty"`
}

// Answer is what the server said to one MCP step.
type Answer struct {
	Request string `json:"request"`
	// Status is the HTTP status, and Body the answer as it came.
	Status int    `json:"status"`
	Body   string `json:"body"`
	// Err says why no request was sent, or why it got no answer.
	Err string `json:"err,omitempty"`
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
	UID   int      `json:"uid"`
	Args  []string `json:"args"`
	Env   []string `json:"env"`
	Stdin string   `json:"stdin"`
	Dir   string   `json:"dir"`
	// Children holds the pids started by spawn steps. The record file is
	// rewritten after each spawn step.
	Children []int `json:"children,omitempty"`
	// Reads and Writes hold the result of each try_read and write_file
	// step, by path: "ok" or the error.
	Reads  map[string]string `json:"reads,omitempty"`
	Writes map[string]string `json:"writes,omitempty"`
	// MCP holds the answer to each mcp step, in order.
	MCP []Answer `json:"mcp,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--fakeagent-child" {
		child(len(os.Args) > 2 && os.Args[2] == "ignore-term")
		return
	}
	// Which run this is: one more than the records that are already there.
	earlier, _ := filepath.Glob(filepath.Join(os.Getenv("FAKEAGENT_RECORD_DIR"), "run-*.json"))
	runNo := len(earlier) + 1
	stdin, _ := io.ReadAll(os.Stdin)
	dir, _ := os.Getwd()
	rec := Record{PID: os.Getpid(), UID: os.Getuid(), Reads: map[string]string{}, Writes: map[string]string{}, Args: os.Args[1:], Env: os.Environ(), Stdin: string(stdin), Dir: dir}
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
		// A well-behaved agent: it says what it did and reports its result.
		done := "fake agent finished " + os.Getenv("ORCH_TASK_KEY")
		report, _ := json.Marshal(map[string]string{"status": "done", "message": done})
		script.Steps = []Step{{Print: done}, {WriteFile: &File{Path: "$ORCH_RESULT_FILE", Content: string(report)}}}
	}

	for _, st := range script.Steps {
		if st.OnRun != 0 && st.OnRun != runNo {
			continue
		}
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
		case st.WriteFile != nil:
			rec.Writes[st.WriteFile.Path] = result(os.WriteFile(os.ExpandEnv(st.WriteFile.Path), []byte(st.WriteFile.Content), 0o644))
			writeRecord(rec)
		case st.TryRead != "":
			_, err := os.ReadFile(st.TryRead)
			rec.Reads[st.TryRead] = result(err)
			writeRecord(rec)
		case st.WaitFile != "":
			for path := os.ExpandEnv(st.WaitFile); ; time.Sleep(20 * time.Millisecond) {
				if _, err := os.Stat(path); err == nil {
					break
				}
			}
		case st.MCP != nil:
			rec.MCP = append(rec.MCP, mcpCall(*st.MCP, len(rec.MCP)+1))
			writeRecord(rec)
		case st.IgnoreTerm:
			signal.Ignore(syscall.SIGTERM)
		case st.Exit != nil:
			os.Exit(*st.Exit)
		}
	}
}

// mcpServer finds the server "ochell" as an agent CLI does: in the file
// that follows --mcp-config in the arguments (or $ORCH_MCP_CONFIG), with
// ${NAME} replaced from the environment. Without such a file it takes the
// address and the token from the environment directly.
func mcpServer() (url, authorization string, err error) {
	file := os.Getenv("ORCH_MCP_CONFIG")
	for i, a := range os.Args {
		if a == "--mcp-config" && i+1 < len(os.Args) {
			file = os.Args[i+1]
		}
	}
	if file == "" {
		return os.Getenv("ORCH_TOOLS_URL"), "Bearer " + os.Getenv("ORCH_TOOLS_TOKEN"), nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", "", err
	}
	var cfg struct {
		Servers map[string]struct {
			Type    string            `json:"type"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", "", fmt.Errorf("%s: %w", file, err)
	}
	srv, ok := cfg.Servers["ochell"]
	if !ok || srv.Type != "http" {
		return "", "", fmt.Errorf("%s has no http server \"ochell\"", file)
	}
	expand := func(s string) string {
		return os.Expand(s, func(name string) string { return os.Getenv(name) })
	}
	return expand(srv.URL), expand(srv.Headers["Authorization"]), nil
}

// mcpCall sends one JSON-RPC request to ochell's MCP server.
func mcpCall(m MCP, id int) Answer {
	method, params := m.Method, any(map[string]any{})
	if m.Tool != "" {
		method = "tools/call"
		args := m.Args
		if args == nil {
			args = map[string]any{}
		}
		params = map[string]any{"name": m.Tool, "arguments": args}
	}
	out := Answer{Request: method + " " + m.Tool}
	url, authorization, err := mcpServer()
	if err == nil && m.TokenFile != "" {
		var raw []byte
		raw, err = os.ReadFile(os.ExpandEnv(m.TokenFile))
		authorization = "Bearer " + strings.TrimSpace(string(raw))
	}
	if err != nil {
		out.Err = err.Error()
		return out
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		out.Err = err.Error()
		return out
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", authorization)
	if method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	out.Status, out.Body = resp.StatusCode, string(answer)
	return out
}

func result(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
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
