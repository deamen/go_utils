// Package result is the agent signal contract: how an agent tells ochell
// how its run ended.
//
// The agent writes a small JSON file at the path ochell gives it in the
// environment variable ORCH_RESULT_FILE. Any agent CLI can do that, whatever
// its output looks like. The file is in a directory of its own for each run,
// outside the working directory, so it is not committed by accident and a
// file from an earlier run is never read.
//
// A run that ends without a valid file has no result, and its ticket waits
// for a human.
package result

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// EnvVar is the environment variable that holds the path of the result file.
const EnvVar = "ORCH_RESULT_FILE"

// FileName is the name of the result file in the directory of a run.
const FileName = "result.json"

// maxSize is the largest result file ochell reads.
const maxSize = 64 << 10

// Status is what the agent says about its run.
type Status string

const (
	// None: the run left no valid result file.
	None Status = ""
	// Done: the work is finished and ready for review.
	Done Status = "done"
	// NeedsInput: the agent needs an answer from a human to go on.
	NeedsInput Status = "needs_input"
	// Blocked: something outside the ticket stops the agent.
	Blocked Status = "blocked"
	// LowConfidence: the agent finished but is not sure of the result.
	LowConfidence Status = "low_confidence"
	// OutOfScope: the ticket asks for something the agent must not or
	// cannot do.
	OutOfScope Status = "out_of_scope"
)

// File is the content of a result file.
type File struct {
	Status Status `json:"status"`
	// Message is a short text for the people on the ticket. It is required
	// for every status but done.
	Message string `json:"message"`
	// PRURL and Branch are optional: the pull request the agent opened and
	// the branch it pushed.
	PRURL  string `json:"pr_url"`
	Branch string `json:"branch"`
}

// Instructions is the part of the prompt that tells the agent to write the
// file. The prompt template includes it as {{.ResultInstructions}}.
const Instructions = `When you stop, for any reason, write a JSON file to the path in the environment variable ` + EnvVar + ` that says how the run ended:

  {"status": "...", "message": "...", "pr_url": "...", "branch": "..."}

"status" is one of:
  done            the work is finished and ready for review
  needs_input     you need an answer from a human before you can go on; put the question in "message"
  blocked         something outside the ticket stops you; say what in "message"
  low_confidence  you finished, but you are not sure the result is right; say why in "message"
  out_of_scope    the ticket asks for something you must not or cannot do; say why in "message"

"message" is a short text for the people on the ticket. "pr_url" and "branch" are optional: set them when you opened a pull request or pushed a branch.
The file is outside the repository; do not copy or commit it. Without it the run counts as having no result, and the ticket waits for a human.`

// Parse checks the content of a result file. Fields it does not know are
// ignored: an agent may add its own.
func Parse(raw []byte) (*File, error) {
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("not a JSON object with the expected fields: %w", err)
	}
	switch f.Status {
	case Done, NeedsInput, Blocked, LowConfidence, OutOfScope:
	case None:
		return nil, errors.New(`no "status"`)
	default:
		return nil, fmt.Errorf("unknown status %q", f.Status)
	}
	f.Message = strings.TrimSpace(f.Message)
	if f.Status != Done && f.Message == "" {
		return nil, fmt.Errorf(`status %s needs a "message"`, f.Status)
	}
	for name, v := range map[string]string{"pr_url": f.PRURL, "branch": f.Branch} {
		if len(v) > 2048 || strings.ContainsAny(v, "\n\r\x00") {
			return nil, fmt.Errorf("%q is not a single line of reasonable length", name)
		}
	}
	return &f, nil
}

// Read reads and checks the result file of a run. runs is the directory
// that holds the directories of all runs, and run the name of this one.
//
// The agent writes the file and owns the directories, so nothing about them
// is trusted: a path that leaves runs through a symlink is refused, and so
// is anything but a regular file of limited size.
func Read(runs, run string) (*File, error) {
	root, err := os.OpenRoot(runs)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := run + "/" + FileName
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxSize)
	}
	return Parse(raw)
}
