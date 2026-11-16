package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"text/template"
	"time"

	"ochell/internal/agent"
	"ochell/internal/config"
	"ochell/internal/policy"
	"ochell/internal/store"
	"ochell/internal/task"
	"ochell/internal/workflow"
)

// WorkflowSource reads the WORKFLOW.md of a repository from its default
// branch: the content, and a version that changes when the content does.
// found is false when the repository has no such file. It returns
// workflow.ErrElsewhere for a repository that it cannot look at.
// workflow.GitHub implements it.
type WorkflowSource interface {
	Read(ctx context.Context, repo string) (raw []byte, version string, found bool, err error)
}

// workflowTimeout is how long a run waits for the repository's file
// before it starts with the last good one.
const workflowTimeout = 20 * time.Second

// UseWorkflow makes the runner read the WORKFLOW.md of each ticket's
// repository at the start of every run. Call it before Start. Without it
// no repository's file is looked at.
func (r *Runner) UseWorkflow(cfg config.Workflow, src WorkflowSource) {
	r.wfCfg, r.wfSrc = cfg, src
}

// flow is what holds for one run: the ticket's tier, narrowed by the
// WORKFLOW.md of its repository, and what else the file sets.
type flow struct {
	workflow.Effective
	// version is that of the file in force; empty: there is none.
	version string
	// prompt is the repository's prompt template; nil: the host's.
	prompt *template.Template
	// hooks are the repository's hooks, by name. They run after the
	// host's.
	hooks map[string][]*template.Template
	// notes are for the log of the run: what of the file is not in force.
	notes []string
}

// host is what this ochell allows a repository's file, for a tier.
func (r *Runner) host(tier policy.Tier) workflow.Host {
	return workflow.Host{
		Tier:             tier,
		AllowHooks:       r.wfCfg.AllowHooks,
		ReviewStatuses:   r.wfCfg.ReviewStatuses,
		LimitsTurns:      agent.LimitsBudget(r.adapter),
		AbsoluteCommands: r.cfg.Launcher == "systemd",
	}
}

// flow returns what holds for the run of t. It reads the WORKFLOW.md of
// the ticket's repository from the default branch, so a change there takes
// effect with the next run, without a restart.
//
// The last file that was valid is kept in the store. It stays in force
// when the file is invalid now or cannot be read; a file that was taken
// off the default branch is no longer in force. What is not in force, and
// each setting that would widen the policy, goes to ochell's log, to the
// log of the run and to the status API.
func (r *Runner) flow(ctx context.Context, t *task.Task, log *slog.Logger) *flow {
	// The level of autonomy comes first, so the file is held against the
	// tier as the level leaves it: both can only narrow.
	f := &flow{Effective: workflow.Effective{Tier: policy.Narrow(r.policy.Tier(t.Tier), t.Autonomy)}, hooks: map[string][]*template.Template{}}
	if r.wfSrc == nil || t.Repo == "" {
		return f
	}
	readCtx, cancel := context.WithTimeout(ctx, workflowTimeout)
	defer cancel()
	raw, version, found, err := r.wfSrc.Read(readCtx, t.Repo)
	if errors.Is(err, workflow.ErrElsewhere) {
		log.Debug("no WORKFLOW.md is read for this repository", "repo", t.Repo, "why", err)
		return f
	}
	row, serr := r.store.Workflow(t.Repo)
	if serr != nil {
		log.Error("cannot read the stored WORKFLOW.md of the repository", "repo", t.Repo, "err", serr)
	}
	if row == nil {
		row = &store.Workflow{Repo: t.Repo}
	}
	// A run that is being stopped did not look: what is stored stays as it
	// is, and the last good file holds for what is left of the run.
	stopping := err != nil && ctx.Err() != nil
	now := time.Now()
	if !stopping {
		row.Checked, row.Error, row.Ignored = now, "", nil
	}
	var file *workflow.File
	switch {
	case stopping:
	case err != nil:
		row.Error = fmt.Sprintf("%s could not be read from the default branch: %v", workflow.FileName, err)
	case !found:
		if row.Version != "" {
			log.Info("the repository has no WORKFLOW.md any more; the host's settings hold alone", "repo", t.Repo, "was", row.Version)
		}
		row.Version, row.Content, row.Loaded = "", "", time.Time{}
	default:
		parsed, perr := workflow.Parse(raw)
		if perr != nil {
			row.Error = fmt.Sprintf("%s on the default branch (%s) is invalid: %v", workflow.FileName, version, oneLine(perr.Error()))
			break
		}
		if row.Version != version {
			log.Info("WORKFLOW.md of the repository changed; the new version is in force", "repo", t.Repo, "version", version, "was", row.Version)
			row.Loaded = now
		}
		file, row.Version, row.Content = parsed, version, string(raw)
	}
	if file == nil && row.Content != "" {
		// The last good file. It was valid when it was stored; an ochell
		// with other rules may have stored it.
		if file, err = workflow.Parse([]byte(row.Content)); err != nil {
			file = nil
			row.Error += fmt.Sprintf("; the stored version %s is not valid for this ochell either: %v", row.Version, oneLine(err.Error()))
			row.Version, row.Content, row.Loaded = "", "", time.Time{}
		}
	}
	if row.Error != "" && !stopping {
		if file != nil {
			row.Error += fmt.Sprintf("; the last good version (%s) stays in force", row.Version)
		} else {
			row.Error += "; there is no earlier good version, so the host's settings hold alone"
		}
		log.Warn("WORKFLOW.md of the repository: "+row.Error, "repo", t.Repo)
		f.notes = append(f.notes, row.Error)
	}
	if file != nil {
		f.Effective = file.Apply(r.host(f.Tier))
		f.version = row.Version
		if f.Prompt != "" {
			// Parse has checked that the text holds placeholders only.
			if f.prompt, err = parse("WORKFLOW.md prompt", f.Prompt); err != nil {
				f.Ignored = append(f.Ignored, "the prompt is ignored: "+oneLine(err.Error()))
			}
		}
		for _, h := range f.Hooks.All() {
			for i, a := range h.Command {
				tmpl, err := parse(fmt.Sprintf("WORKFLOW.md hooks.%s[%d]", h.Name, i), a)
				if err != nil {
					f.Ignored = append(f.Ignored, fmt.Sprintf("hooks.%s is ignored: %s", h.Name, oneLine(err.Error())))
					delete(f.hooks, h.Name)
					break
				}
				f.hooks[h.Name] = append(f.hooks[h.Name], tmpl)
			}
		}
		for _, line := range f.Ignored {
			log.Warn("WORKFLOW.md of the repository: a setting is ignored", "repo", t.Repo, "version", f.version, "setting", line)
			f.notes = append(f.notes, line)
		}
		row.Ignored = f.Ignored
	}
	if stopping {
		return f
	}
	if err := r.store.SaveWorkflow(*row); err != nil {
		log.Error("cannot store the WORKFLOW.md of the repository", "repo", t.Repo, "err", err)
	}
	return f
}

// ReviewStatus returns the Jira status that the WORKFLOW.md of a ticket's
// repository chooses for the hand-over, or "" when the host's own holds:
// the file in force names none, or one that the host does not list.
func (r *Runner) ReviewStatus(source, key string) string {
	if r.wfSrc == nil || len(r.wfCfg.ReviewStatuses) == 0 {
		return ""
	}
	tk, err := r.store.Ticket(source, key)
	if err != nil || tk == nil || tk.Repo == "" {
		return ""
	}
	row, err := r.store.Workflow(tk.Repo)
	if err != nil || row == nil || row.Content == "" {
		return ""
	}
	file, err := workflow.Parse([]byte(row.Content))
	if err != nil {
		return ""
	}
	return workflow.AllowedStatus(file.ReviewStatus, r.wfCfg.ReviewStatuses)
}

// WorkflowStatus is what ochell knows about the WORKFLOW.md of one
// repository.
type WorkflowStatus struct {
	Repo string `json:"repo"`
	// Version is that of the file in force; empty: none is.
	Version string `json:"version,omitempty"`
	// Loaded is when that version came into force, and Checked when ochell
	// last looked at the default branch: at the start of the last run of a
	// ticket of the repository.
	Loaded  *time.Time `json:"loaded,omitempty"`
	Checked time.Time  `json:"checked"`
	// Error says why what the default branch has now is not in force.
	Error string `json:"error,omitempty"`
	// Ignored are the settings of the file in force that the last run did
	// not use, because they would widen the host's policy or the host
	// does not allow them.
	Ignored []string `json:"ignored,omitempty"`
}

// workflows returns the status of every repository's file, for Status.
func (r *Runner) workflows() ([]WorkflowStatus, error) {
	if r.wfSrc == nil {
		return nil, nil
	}
	rows, err := r.store.Workflows()
	if err != nil {
		return nil, err
	}
	var out []WorkflowStatus
	for _, w := range rows {
		st := WorkflowStatus{Repo: w.Repo, Version: w.Version, Checked: w.Checked, Error: w.Error, Ignored: w.Ignored}
		if !w.Loaded.IsZero() {
			st.Loaded = &w.Loaded
		}
		out = append(out, st)
	}
	return out, nil
}
