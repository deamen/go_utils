---
# WORKFLOW.md: how tickets are worked in this repository. ochell reads it
# from the default branch at the start of every run (workflow.enabled in
# ochell's config.yaml), so a change holds once it is merged.
#
# It can only narrow what the host's policy gives a ticket. A setting that
# would widen it is ignored and reported; a setting that ochell does not
# know makes the whole file invalid, and the last good version stays in
# force. "ochell workflow-check --file WORKFLOW.md" checks it before a merge.

# Stricter than the ticket's tier, or left out:
plan_gate: required        # required | skip
pr_review: required        # required | sampled
auto_merge: never          # never | after_ci
max_turns: 60              # at most the tier's own limit

# The Jira status at the hand-over: one of workflow.review_statuses.
review_status: Code Review

# Run after the host's hooks of the same name, when the host allows a
# repository's hooks (workflow.allow_hooks). Placeholders: {{.ID}}
# {{.Source}} {{.Key}} {{.Repo}} {{.Branch}}.
hooks:
  after_create: [/bin/sh, -c, 'npm ci']
  before_run: [/bin/sh, -c, 'git fetch origin && git merge --ff-only origin/main || true']
  # after_run: []
---
You are the digital employee assigned {{.Source}} ticket {{.Key}} ({{.URL}}).
Use twg to read the ticket. Work in this repository ({{.Repo}}), on the branch
in ORCH_TASK_BRANCH, and open a pull request against main.

Rules of this repository:
- Run `npm test` and `npm run lint` before you push.
- Keep a change to one concern; say in the pull request what you verified.

{{.RunContext}}

{{.ResultInstructions}}
