package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Claude runs Claude Code in print mode with its event stream as output:
//
//	claude -p --output-format stream-json --verbose [--resume <session>]
//
// The prompt always goes on stdin. Checked against Claude Code 2.1.311: in
// print mode, stream-json is refused without --verbose.
type Claude struct{}

// claudeOwned are the flags this adapter sets itself; --bare makes Claude
// Code ignore the OAuth token. None of them may be in agent.args.
var claudeOwned = []string{"--output-format", "--resume", "-r", "--continue", "-c", "--bare"}

// checkClaudeArgs refuses configured arguments that the adapter must own.
func checkClaudeArgs(args []string) error {
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		if slices.Contains(claudeOwned, name) {
			if name == "--bare" {
				return errors.New("agent.args: --bare cannot be used with the claude adapter: it makes Claude Code ignore the OAuth token")
			}
			return fmt.Errorf("agent.args: %s is set by the claude adapter; remove it", name)
		}
	}
	return nil
}

func (Claude) command(run Run, extra ...string) Command {
	args := slices.Clone(run.Args)
	if !slices.Contains(args, "-p") && !slices.Contains(args, "--print") {
		args = append(args, "-p")
	}
	args = append(args, "--output-format", "stream-json", "--verbose")
	return Command{Args: append(args, extra...), Stdin: strings.NewReader(run.Prompt)}
}

func (c Claude) Start(run Run) (Command, error) { return c.command(run), nil }

// sessionID is what a Claude Code session id may look like. The id comes
// out of the agent's output and goes back into an argument, so nothing else
// is accepted: with the systemd launcher a '$' in an argument is expanded.
var sessionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func (c Claude) Resume(run Run, session string) (Command, error) {
	if !sessionID.MatchString(session) {
		return Command{}, fmt.Errorf("%w: %q is not a session id", ErrNoResume, session)
	}
	return c.command(run, "--resume", session), nil
}

func (Claude) Output(on func(Event)) Output {
	return &claudeOutput{other: tail{max: tailSize}, on: on}
}

// Limits of the output reader. A line of the stream can be large (a tool
// result); one that is longer than maxLine is skipped.
const (
	maxLine    = 8 << 20
	maxMessage = 64 << 10
)

// claudeEvent is the part of a stream-json line that ochell uses. The
// stream has more event types and fields; they are ignored.
type claudeEvent struct {
	Type      string  `json:"type"`
	Subtype   string  `json:"subtype"`
	SessionID string  `json:"session_id"`
	Result    string  `json:"result"`
	IsError   bool    `json:"is_error"`
	CostUSD   float64 `json:"total_cost_usd"`
	Usage     *struct {
		Input      int64 `json:"input_tokens"`
		Output     int64 `json:"output_tokens"`
		CacheRead  int64 `json:"cache_read_input_tokens"`
		CacheWrite int64 `json:"cache_creation_input_tokens"`
	} `json:"usage"`
	Message *struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"message"`
}

// claudeOutput reads the event stream line by line. Stdout and stderr
// arrive mixed, so lines that are not events are expected: they are kept
// as the message of a run that printed no result.
type claudeOutput struct {
	mu       sync.Mutex
	line     []byte
	skipping bool // inside a line that is longer than maxLine

	// on is told about the session as soon as the stream names it.
	on func(Event)

	rep       Report
	gotResult bool
	lastText  string // text of the last assistant message
	other     tail   // lines that are not events
}

func (o *claudeOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			o.add(p)
			break
		}
		o.add(p[:i])
		if !o.skipping {
			o.event(o.line)
		}
		o.line, o.skipping = o.line[:0], false
		p = p[i+1:]
	}
	return n, nil
}

func (o *claudeOutput) add(p []byte) {
	if o.skipping {
		return
	}
	if len(o.line)+len(p) > maxLine {
		o.line, o.skipping = o.line[:0], true
		return
	}
	o.line = append(o.line, p...)
}

func (o *claudeOutput) event(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	var ev claudeEvent
	if line[0] != '{' || json.Unmarshal(line, &ev) != nil || ev.Type == "" {
		o.other.Write(append(line, '\n'))
		return
	}
	if sessionID.MatchString(ev.SessionID) && ev.SessionID != o.rep.SessionID {
		o.rep.SessionID = ev.SessionID
		if o.on != nil {
			o.on(Event{SessionID: ev.SessionID})
		}
	}
	switch ev.Type {
	case "assistant":
		if ev.Message == nil {
			return
		}
		var text []string
		for _, c := range ev.Message.Content {
			if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
				text = append(text, c.Text)
			}
		}
		if len(text) > 0 {
			o.lastText = strings.Join(text, "\n")
		}
	case "result":
		o.gotResult = true
		o.rep.Failed = ev.IsError
		o.rep.Message = ev.Result
		o.rep.CostUSD = ev.CostUSD
		if u := ev.Usage; u != nil {
			o.rep.Usage = Usage{InputTokens: u.Input, OutputTokens: u.Output, CacheReadTokens: u.CacheRead, CacheWriteTokens: u.CacheWrite}
		}
	}
}

// Report gives the final message of the result event. A run that ended
// without one (it was stopped, or Claude Code could not start) gives the
// last thing the agent said, or else what was printed besides the events.
func (o *claudeOutput) Report() Report {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.line) > 0 && !o.skipping {
		// A last line without a newline.
		o.event(o.line)
		o.line = o.line[:0]
	}
	rep := o.rep
	if strings.TrimSpace(rep.Message) == "" {
		rep.Message = o.lastText
	}
	if strings.TrimSpace(rep.Message) == "" || !o.gotResult {
		if extra := strings.TrimSpace(o.other.Report().Message); extra != "" {
			rep.Message = strings.TrimSpace(rep.Message + "\n" + extra)
		}
	}
	if len(rep.Message) > maxMessage {
		rep.Message = rep.Message[len(rep.Message)-maxMessage:]
	}
	return rep
}
