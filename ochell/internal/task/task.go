// Package task defines the source-independent unit of work handed to the agent.
package task

import (
	"context"
	"time"
)

type Task struct {
	// ID is unique per task and used for log file names.
	ID string
	// Source is "jira" or "linear".
	Source string
	// Key is the human readable ticket key, e.g. "ENG-123".
	Key   string
	Title string
	URL   string
	// Context is optional extra text from the source (e.g. Linear promptContext).
	Context string
	// DeliveryID identifies the webhook delivery for de-duplication.
	DeliveryID string
	Received   time.Time

	// Prompt is rendered by the runner from the prompt template.
	Prompt string

	// Optional callbacks to report progress back to the source.
	OnStart  func(ctx context.Context, t *Task) error
	OnFinish func(ctx context.Context, t *Task, result Result) error
}

type Result struct {
	ExitCode int
	Err      error
	LogFile  string
	Duration time.Duration
	// Tail holds the last part of the agent output.
	Tail string
}
