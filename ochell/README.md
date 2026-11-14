# ochell
Webhook receiver for the "digital employee" POC. When a Jira or Linear ticket is assigned to the digital employee, it authenticates the webhook and launches one agent CLI process (e.g. Claude Code) with a prompt describing the ticket. The agent then uses `twg` to read the ticket, does the work and opens a PR.

```
Jira (webhook / Automation) ─┐                ┌──────────────────────┐   exec (no shell)   ┌───────────┐
                             ├─► ngrok ──────►│ ochell               ├────────────────────►│ claude -p │
Linear (agent app)  ─────────┘  IP policy +   │ verify → parse →     │  one per ticket     └───────────┘
                                verify-webhook │ dedup → queue → run  │
                                               └──────────┬───────────┘
                                                          └─► Linear agent activities (ack / result)
```

## Supported sources
| Source | Endpoint (default) | Authentication | Trigger |
|---|---|---|---|
| Jira system webhook | `POST /webhooks/jira` | `X-Hub-Signature: sha256=<HMAC>` with the webhook secret, and `timestamp` within `max_skew` (2h) | `jira:issue_updated` whose changelog changes `assignee` to the bot, or `jira:issue_created` already assigned to the bot. `comment_created` by a person on a ticket ochell holds (a follow-up) |
| Jira Automation "Send web request" | `POST /webhooks/jira-automation` | Shared token in a header (`Authorization: Bearer …` by default). Automation cannot sign payloads. | An authenticated request that names the bot as assignee. Without `bot_account_id`, any authenticated request (the rule decides when to fire) |
| Linear agent app (`actor=app`) | `POST /webhooks/linear` | `Linear-Signature` HMAC and `webhookTimestamp` within 60s | `AgentSessionEvent` `created` (issue delegated to, or agent mentioned) |

Behaviour common to all sources:
- **Responses:**
  - 200 when a task is queued, ignored or a duplicate, and when a ticket is not started because no repository is mapped to it;
  - 401 when authentication fails;
  - 400 when the payload is unusable, for example a Jira Automation request that names no assignee;
- **Duplicate deliveries:** a signed request is dropped when its body, or its `X-Atlassian-Webhook-Identifier` / `Linear-Delivery` id, was seen before. The body counts because the signature covers it; the id is a header that a replayed request can change. Both are kept in the store for 24 hours, also across a restart.
- **Replay:** a signed request is rejected with 401 when its timestamp (`timestamp` for Jira, `webhookTimestamp` for Linear) is further than `max_skew` from now. The default is 60s for Linear and 2h for Jira: Jira retries a failed delivery up to five times, 5 to 15 minutes apart, and a retry may carry the timestamp of the event. Jira Automation requests carry no timestamp.
- **One run per ticket:** a ticket that is already queued or running is not started again. A second assignment is answered with 200 `already in progress`. A new Linear session on such a ticket that brings no message gets a `response` activity that says so, which closes that session; the result is posted in the first session. A message to a busy ticket is kept for its next run (see *Messages during a run* below).
- **Linear session updates:** the orchestrator posts a `thought` activity right away, because Linear expects one within 10s. When the run ends it posts what the agent reported in its result file (see [The result file](#the-result-file)): a `response` for finished work, an `elicitation` for anything that needs a human. A run that failed, timed out or was stopped gets an `error`.
- **Jira ticket updates:** with the Jira API configured (see [Jira API access](#jira-api-access)), ochell comments on a Jira ticket when a run starts, and again when it ends, with the same text a Linear session gets: the agent's message and its pull request, its question, or why the run failed. A ticket that was accepted but not started (no repository, attempts used up) gets a comment that says so. With `review_status` the ticket is also moved to that status when the agent reports its work as done. Without the API a Jira ticket gets no answer.
- **Jira follow-ups:** a comment that a person writes on a Jira ticket starts a new run of the ticket with that comment, for example the answer to a question the agent asked, or a remark of the reviewer. It needs the *Comment created* event on the system webhook (see [Jira system webhook](#jira-system-webhook-recommended)).
  - The run continues the **same agent session** as the ticket's earlier run when the adapter has sessions (`claude`), in the same working directory. The comment is in the run context of the prompt, marked as a message from a person that does not change what the agent may do.
  - **Comments by the bot account are ignored** (`bot_account_id`). That covers what ochell writes itself and what the agent writes with its ticket tool, so the agent cannot wake itself up. This is why ochell's API token and the agent's `twg` must use the same Jira account.
  - **Only tickets that ochell holds:** a ticket it has worked on that waits for a human, is in review, or failed. A comment on a ticket that ochell never worked on, that is done or that was released is ignored: people talk to each other there. A comment on a ticket whose issue is assigned to someone else is ignored as well.
  - **Every comment of a person on such a ticket starts a run,** also one that was meant for a colleague. Jira has no way to address the agent only.
  - A comment that arrives while the ticket has a run is kept (see below).
  - Who wrote the comment is checked against `allowed_follow_ups` (see [Guards and the admin channel](#guards-and-the-admin-channel)).
  - **Jira Automation stays a start-only trigger.** It cannot sign requests and has no delivery id, so follow-ups work with the system webhook only.
  - A comment whose first line is `/stop` stops the ticket (see *Stopping from the ticket* below).
- **Stopping from the ticket:** a person can stop the work on a ticket without touching ochell.

  | How | Who may |
  |---|---|
  | Linear: the **stop** control of the agent session (the `stop` signal of a `prompted` event) | the people of `allowed_follow_ups` |
  | Jira: a comment whose **first line is `/stop`**, and nothing else on that line. More lines may follow | the people of `allowed_follow_ups` |
  | Jira: the ticket is **taken away from the bot** (assigned to someone else, or to nobody) | whoever Jira lets do that |
  | Linear: the issue is taken away from the agent (an `Issue` update that changes the delegate) | whoever Linear lets do that |
  | The ticket is **closed** in the tracker while it is queued or running | whoever the tracker lets do that |

  - **What is stopped:** a running agent with all its processes (as at the time limit); a run that is still queued, which then never starts; and a ticket that only waited, which is released.
  - **The ticket becomes `cancelled`.** It is not started again, and comments on a Jira ticket start nothing, until it is assigned again. Messages that waited for its next run are dropped. The run has the outcome `cancelled`.
  - **The ticket shows it:** a `response` in the Linear session, a comment on the Jira ticket, that says who stopped it and how, and that it has to be assigned again to go on.
  - A closed ticket becomes `done` once its run has ended, and its working directory is removed as for any closed ticket.
  - **Jira may not send the unassign event** when the webhook's filter is `assignee = <bot>`: the ticket no longer matches after the change. ochell handles the event when it arrives, and [the poller](#the-poller) finds the ticket otherwise. That was not tested against a real Jira (MMZ-94).
  - The Linear events were not checked against Linear: where the payload carries the stop signal, and what an issue update looks like when the delegate changes. The second also needs the app's webhook to subscribe to **Issues**, and is only acted on when the payload names this app's user as the earlier delegate.
- **Messages during a run:** a comment or reply that arrives while a ticket has a queued or running run is kept in the store, and **delivered with the ticket's next run**, which ochell queues itself as soon as the current one has ended. Several messages are delivered together, oldest first, each in its own `<comment>` block of the run context.
  - The run that was going ends as it would have: its result is posted, and then the next run starts.
  - A Linear session is told that the message is queued. A Jira ticket is not, so that ochell does not answer every comment; the webhook is answered with `queued for the next run`.
  - The next run reports to the Linear session that the last message came in.
  - A new Linear session on a busy ticket that comes with a message (the agent was mentioned in a comment) is treated the same way. One without a message is told that the ticket is already being worked on, as before.
  - A run that ochell starts again by itself (a retry, a run after a restart) takes the waiting messages along.
  - At most 50 messages wait per ticket; a further one is answered with 503.
- **Linear follow-ups:** a reply in a Linear agent session (the `prompted` event) starts a new run of the ticket with that message, for example the answer to a question the agent asked.
  - The run continues the **same agent session** as the ticket's earlier run when the adapter has sessions (`claude`), in the same working directory. The message is in the run context of the prompt, marked as a message from a person that does not change what the agent may do.
  - The session gets a `thought` at once, and the result of the run when it ends, like a first run.
  - A message that arrives while the ticket has a run is kept (see below), and the session is told so.
  - A reply in a session of a ticket that ochell has never worked on is taken as a new assignment.
  - Who wrote the reply is checked against `allowed_follow_ups` (see [Guards and the admin channel](#guards-and-the-admin-channel)). Whether the payload names the author of a prompt was not checked against Linear; without one, the creator of the session counts.
  - The `stop` signal stops the ticket (see *Stopping from the ticket* above).

### The poller
A webhook is fast, but it can be lost: ochell was down, the network failed, or the tracker does not send the event at all (Jira and the unassign event). So ochell also asks each tracker for the bot's open tickets, **at start and then every `poller.interval`** (default 5m; `0s` turns it off). The webhook stays for speed; the poll is for correctness.

| The poller finds | It does |
|---|---|
| an open ticket of the bot that ochell has **never seen** | starts it, as its webhook would have |
| a ticket with a queued or running task that is **closed** in the tracker | stops it; the ticket becomes `done` |
| a ticket with a queued or running task that is **no longer the bot's** | stops it; the ticket becomes `cancelled`, and is told why |
| any other ticket that ochell knows | nothing |

- **Which trackers:** Jira needs the API access (`sources.jira_api`); Linear needs the installed app and its token. A tracker that cannot be asked is not polled; the log says so at start.
- **A ticket that ochell knows is never started by the poller.** One that waits for a human or is in review has had its run. One that a person stopped or released (`cancelled`) stays stopped until it is assigned again, and only a webhook says that. So a new assignment of a ticket that ochell already knows is not recovered when its webhook is lost: assign it once more.
- **On the first start with the poller, every open ticket of the bot is new to ochell and is started.** Look at what `ochell jira-check` lists before you turn it on, or pause first (`ochell pause`) and look at `ochell status`. `agent.queue_size` bounds how many wait.
- **Linear sessions:** a ticket that came through a webhook has an agent session to report to. One that the poller finds has none, so ochell opens a session on the issue itself and reports there.
- **Who assigned it** is read from the ticket's history (Jira: the last change of the assignee to the bot, else the creator; Linear: the last change of the delegate to the agent, else the creator). `allowed_assigners` holds for the poller as for a webhook: a ticket whose assigner is not on the list, or cannot be found, is not started, and the log says so once.
- **Before it stops anything, the poller asks the tracker about that one ticket.** A ticket that is missing from the list but open and still the bot's is left alone: the search may be behind, or `jira_api.jql` narrower than the bot's tickets. A list that cannot be read changes nothing at all.
- **Linear and mentions:** an issue on which the agent was only mentioned was never delegated to it, so it is not on the list. Its run is stopped by the poller only when the issue is closed.
- **Jira Automation without `bot_account_id`** can start tickets that are not assigned to the bot. With that configuration the poller starts missed tickets but stops none.
- Not covered: a comment whose webhook was lost is not recovered.

### Retry and stall detection
ochell starts a ticket again by itself in two cases. Both count as an attempt, so `agent.max_attempts` bounds them.

- **A failure that is not the task's own.** A run that failed and whose final message matches one of `agent.retry.patterns` (with the `plain` adapter: the last 4 KB of its output) failed for a temporary reason. The default patterns are a rate limit, "overloaded", an API error 429 or 5xx, a gateway error and a broken connection. The ticket is queued again and starts after a wait: `retry.backoff` (1m) after the first attempt, doubled with each further attempt of the ticket, up to `retry.max_backoff` (30m).
  - A failed run that matches no pattern is a task failure and is not retried: the ticket is `failed`.
  - When the attempts are used up, the ticket is `failed`, and gets the error of the last run.
  - `patterns: []` turns the retry off. The default patterns were not checked against what Claude Code prints for each of these errors; look at a failed run's log and add what you see.
  - With the `claude` adapter, a run whose result event says `is_error` counts as failed even when the process exits with status 0.
- **A stalled agent.** With `agent.stall_timeout` set, an agent that wrote no output for that long is stopped, with all its processes, and the ticket is started again after the same wait. After the last attempt the ticket waits for a human with the reason `stalled`.
  - It is off by default (`0s`). Silence is all ochell can see: a slow test suite looks the same as a hung agent. Set it well above the longest silent step you expect.
- **The ticket is told each time:** a `thought` in a Linear session, a comment on a Jira ticket, that says why the run ended and when the next one starts.
- **The next run is told as well.** Its run context says that the earlier attempt was cut off by an outside error, or was stopped as stalled, and that the agent must check what is already done.
- While a ticket waits for its retry it is `queued`: a new assignment in that time is answered with `already in progress`. A wait is kept across a restart.

### Stopping agents and shutting down
- **A stop ends the whole agent**, not only its top process: sub-agents, MCP servers and git children too. ochell sends SIGTERM, and SIGKILL after `agent.stop_grace` (10s). This happens at `agent.timeout`, at `agent.stall_timeout` and on shutdown.
  - With the `systemd` launcher ochell stops the unit, and systemd signals every process in it.
  - With the `direct` launcher the agent runs in its own process group and ochell signals the group. A child that leaves the group (`setsid`) is not reached; use the `systemd` launcher where that matters. When the agent exits by itself, what it left running in its group is killed as well.
- **Shutdown** (SIGTERM or Ctrl-C): ochell stops accepting webhooks and waits up to `agent.drain_timeout` (30s) for running agents to finish. Then it stops the ones still running. A second signal ends the wait at once. Tasks that were queued but not started stay in the store and run after the next start.
  - If ochell runs as a systemd service, set the service's `TimeoutStopSec` above `drain_timeout` plus `stop_grace`, or systemd kills ochell first.
- **After a crash** (ochell was killed, or the host went down): at the next start, queued tasks run as usual, and a run that was in progress is closed as `interrupted`.
- **A run that ochell cut short or did not see the end of is started again** after the restart, as a new attempt of its ticket. That holds for a run that a shutdown stopped and for one that a crash interrupted.
  - The new attempt runs in the same working directory and, when the agent adapter has sessions (`claude`), in the same agent session. ochell stores the session as soon as the agent names it, not only at the end of a run.
  - Its prompt has the **recovery note** in the run context: the agent may have done part of the work, and must check git, the pull request and the ticket's comments before it repeats anything with an effect outside the working directory.
  - The ticket is told that the run was cut off and is queued again: a `thought` in a Linear session, a comment on a Jira ticket.
  - It counts as an attempt. A ticket that has used up `agent.max_attempts` is not started again: it waits for a human with the reason `interrupted`, and gets an error that says so.
  - **What the crash left running:** with the `systemd` launcher the unit of the interrupted run may still be there, so ochell stops it by its task id before the new attempt starts. With the `direct` launcher ochell cannot find the old agent; it runs on until it ends by itself, next to the new attempt. That is one more reason to deploy with `systemd`.

## Build
```
make test                 # go vet + go test -race
make                      # cross-compile for linux/darwin/windows on amd64/arm64
go build -o ochell .
```

### End-to-end tests
`go test ./e2e/` (part of `make test`) starts a real `ochell` process and sends it signed webhooks. The agent is [e2e/fakeagent](e2e/fakeagent/main.go), a scripted stand-in that records its arguments, environment, stdin and working directory, Linear is a fake API that records the activities ochell posts, and Jira is a fake site ([jiratest](internal/tracker/jiraapi/jiratest/jiratest.go)) with tickets and comments. No real agent or tracker is involved.

A test uses the harness in [e2e/harness.go](e2e/harness.go):
```go
o := e2e.Start(t, e2e.Options{Script: []e2e.Step{{Print: "done"}, e2e.Exit(0)}})
id := o.LinearCreated("ENG-1", "session-1", "context").TaskID(t)
run := o.WaitRun(id, 15*time.Second)          // exit code and log of the run
rec := o.WaitRecords(1, 5*time.Second)[0]     // what the agent was started with
acts := o.WaitActivities("session-1", 2, 10*time.Second)
```
The harness uses the direct launcher by default. `e2e.UseFakeSystemd` selects the systemd launcher with the real launch and stop scripts and stand-ins for `systemd-run` and `systemctl`, which covers the path through the scripts in CI.

### Tests on the VM
CI has no systemd, so what only real systemd can show runs on the VM. Set up the systemd launcher first (see [Launchers](#launchers)).

1. As root, check the scripts as ochell calls them, through `sudo`:
   ```
   scripts/check-launch-scripts.sh <ochell-user>
   ```
   Two older scripts check the mechanism itself, without the launch scripts: `scripts/check-systemd-launcher.sh` and `scripts/check-agent-token.sh`.
2. As the ochell user, run the VM-only end-to-end tests. They are the tests that call `e2e.RequireVM(t)`, and are skipped unless `OCHELL_E2E_VM=1`. The VM needs no Go toolchain: build on a development machine with `make vmtest`, copy `vmtest/` to a directory on the VM that the agent user can read, and run
   ```
   OCHELL_E2E_VM=1 OCHELL_E2E_BIN_DIR=$PWD OCHELL_E2E_VM_WORKSPACE=/work ./e2e.test -test.v -test.run OnVM
   ```
   For these tests `launcher.conf` needs `ALLOWED_ENV='^FAKEAGENT_[A-Z_]+$'`, because the fake agent is configured through `FAKEAGENT_*` variables.

## Commands
```
ochell serve --config config.yaml                 # default command
ochell ngrok-sync --config config.yaml [--dry-run] [--loop]
ochell linear-install --config config.yaml        # prints the agent install URL
ochell jira-check --config config.yaml [--comment-on KEY]   # check the Jira API access
ochell version

# commands to the running ochell, over its admin socket (see "Guards and the admin channel")
ochell status --config config.yaml                # paused or running; what is queued and running
ochell pause  --config config.yaml                # hold the queue: no new run starts
ochell resume --config config.yaml
ochell reset <jira|linear> <KEY> --config config.yaml   # reset the attempts of a ticket
ochell stop  <jira|linear> <KEY> --config config.yaml   # stop the run of a ticket and release it
```

## Configuration
Configuration comes from YAML and/or flags. Precedence is **defaults < YAML < flags**, and a flag only overrides YAML when it is given. `${VAR}` in YAML is replaced from the environment, so secrets can stay out of the file. See [examples/config.yaml](examples/config.yaml) for every option.

Common flags (run `ochell serve -h` for all of them):

| Flag | Meaning |
|---|---|
| `--http`, `--http-addr`, `--http-port` | Enable the HTTP listener and set its address and port separately |
| `--https`, `--https-addr`, `--https-port`, `--tls-cert`, `--tls-key` | Same for HTTPS (TLS 1.2+) |
| `--admin-socket` | Unix socket of the admin channel (default `ochell.sock`); see [Guards and the admin channel](#guards-and-the-admin-channel) |
| `--poll-interval` | How often ochell asks the trackers for the bot's open tickets (default `5m`; `0s`: never); see [The poller](#the-poller) |
| `--store-path` | File that holds the tickets, the task queue and the handled deliveries (default `ochell.db`); see [The store](#the-store) |
| `--agent-cmd` | Agent CLI executable (default `claude`) |
| `--agent-arg` | Agent argument; repeatable; replaces the YAML `args` (default `-p`). Go template: `{{.Key}}`, `{{.Source}}`, `{{.ID}}`. Keep ticket text (`{{.Title}}`, `{{.URL}}`, `{{.Context}}`, `{{.Prompt}}`) out of arguments; see [The prompt](#the-prompt) |
| `--agent-prompt-via` | `stdin` (default) or `arg` |
| `--agent-adapter` | Kind of agent CLI: `plain` (default) or `claude`; see [Agent adapters](#agent-adapters) |
| `--agent-launcher` | `direct` (default) or `systemd`; see [Launchers](#launchers) |
| `--agent-env-pass` | Variable the agent inherits from ochell's environment; repeatable; replaces the default list (see [Agent environment](#agent-environment)) |
| `--agent-stall-timeout` | Stop an agent that wrote no output for this long, and start the ticket again (default `0`: never); see [Retry and stall detection](#retry-and-stall-detection) |
| `--agent-workdir`, `--agent-timeout`, `--agent-max-concurrent`, `--agent-max-attempts`, `--agent-log-dir`, `--agent-run-dir` | Execution settings |
| `--agent-stop-grace`, `--agent-drain-timeout` | Time between SIGTERM and SIGKILL when an agent is stopped; how long a shutdown waits for running agents (see [Stopping agents and shutting down](#stopping-agents-and-shutting-down)) |
| `--jira-webhook`, `--jira-webhook-secret`, `--jira-bot-account-id` | Jira system webhook source |
| `--jira-automation`, `--jira-automation-header`, `--jira-automation-token` | Jira Automation source |
| `--linear`, `--linear-secret`, `--linear-client-id`, `--linear-client-secret`, `--linear-redirect-url` | Linear agent source |

Example without a YAML file:
```
JIRA_SECRET=... ochell serve --http-addr 127.0.0.1 --http-port 8080 \
  --jira-webhook --jira-webhook-secret "$JIRA_SECRET" --jira-bot-account-id 712020:... \
  --agent-cmd claude --agent-arg -p
```

The agent runs without a shell, with its working directory set to `workdir` (rendered per task). Output goes to `<log_dir>/<task id>.log`.

### The store
ochell keeps its durable state in one SQLite file, `store.path` (default `ochell.db` in the working directory). It is created when missing, readable by its owner only, and updated in place when a newer ochell needs more tables. It holds:
- the **tickets** ochell has worked on: state (see [Ticket states](#ticket-states)), number of attempts, working directory, and the agent's session id for a resume;
- the **runs** of each ticket, which are also the task queue: when a run was received, started and ended, its outcome, exit code and log file, the context that came with the webhook and the Linear session to report to, and what the agent adapter read from it (final message, session id, cost, token counts);
- the **webhook deliveries** handled in the last 24 hours.

So a restart loses no queued task, and a retried or replayed delivery from before the restart is still recognised. SQLite keeps two more files next to it while ochell runs (`-wal` and `-shm`); copy all three, or stop ochell first, when you back it up.

Put the file where the agent cannot read or write it: it holds ticket text, and later the agent's session ids. With the `systemd` launcher that is any directory of the ochell user.

### Jira API access
The webhooks only bring events in. For what ochell does on its own in Jira (commenting on a ticket when a run starts and ends, changing a status, and finding the bot's tickets for [the poller](#the-poller)) it needs the Jira REST API, with the API token of the digital employee's account:

```yaml
sources:
  jira_api:
    base_url: https://example.atlassian.net
    email: digital.employee@example.com
    token: ${JIRA_API_TOKEN}
```

- **Use the same Jira account as the agent's `twg`.** What ochell writes then comes from the bot account, like what the agent writes.
- **`jql`** selects the bot's open tickets, which is what the poller starts from. The default is `assignee = currentUser() AND statusCategory != Done`: the account that owns the token, so no account id is needed.
- **Check it** with `ochell jira-check --config config.yaml`. It lists the tickets that the JQL selects; with `--comment-on KEY` it also adds a test comment to that ticket.
- **`review_status`** is optional: the status, for example `In Review`, that a ticket is moved to when the agent reports its work as done. The ticket's workflow must have a transition to it from where the ticket is. If the move fails, ochell logs a warning, and the comment is there all the same.
- The token is ochell's own. It is not passed to the agent.
- Without `base_url` ochell runs as before, and nothing that needs the API happens.

Only [internal/tracker/jiraapi](internal/tracker/jiraapi/jiraapi.go) calls the Jira API. The rest of ochell uses the small interface in [internal/tracker](internal/tracker/tracker.go) (`Assigned`, `Comment`, `SetStatus`), so another way to reach Jira, such as `twg`, can be added behind it.

### Repositories
`repos` says which repository a ticket belongs to. ochell needs it to prepare a workspace; the agent is told the repository in its prompt and in `ORCH_TASK_REPO`.

```yaml
repos:
  - {source: jira, project: DEV, label: frontend, repo: git@github.com:example/web.git}
  - {source: jira, project: DEV, repo: git@github.com:example/backend.git}
  - {source: linear, project: ENG, repo: git@github.com:example/engine.git}
```

- **`project`** is the Jira project key or the Linear team key: the part of the ticket key before the number (`DEV` in `DEV-42`). `"*"` matches every project.
- **`source`** is `jira` or `linear`; leave it out to match both.
- **`label`** is optional and narrows an entry to tickets with that label, or in Jira that component. Labels come from the webhook payload: the Jira system webhook has them; for Jira Automation add `"labels": "{{issue.labels}}"` to the request body. Whether the Linear agent session payload carries labels has not been checked against Linear.
- **The first entry that matches wins**, so put the narrower entries first.
- **A ticket that no entry matches is not started.** It is recorded as `waiting` with the reason `no_repo_mapping`, the request is answered with 200 `not started: …`, ochell logs a warning, and a Linear session is told why. After the mapping is added, assign the ticket again.
- With no `repos` at all, every ticket runs, without a repository.

### Guards and the admin channel
Limits on what starts a run, and one way to talk to the running ochell.

- **Attempt cap:** `agent.max_attempts` (default 5; 0 for no limit) is how many runs one ticket may have. Every started run counts, whoever asked for it, also the ones ochell starts by itself (a retry, a run after a restart). **A message from a person (a reply in the ticket's Linear session, a comment on the Jira ticket) starts the count again**: the cap is there to stop what runs without anyone looking, and here someone looked. The attempt number in the prompt still counts every run. When a ticket has used them up, a new assignment starts nothing: the request is answered with 200 `not started: <KEY> has used its N attempts`, the ticket waits for a human with the reason `escalation`, ochell logs a warning, and a Linear session is told. After someone has looked at it, `ochell reset <jira|linear> <KEY>` sets the count back to zero; then assign the ticket again.
- **Pause:** `ochell pause` holds the queue. No new run starts; running agents go on; webhooks are still accepted and queued. `ochell resume` ends it, and the queued tasks run. Both take effect at once, without a restart, and a pause is kept across a restart. `ochell status` says which it is, and how many tasks are queued and running.
- **Assigner allowlist:** `allowed_assigners` of a source, when it is not empty, lists who may assign work. Anyone else is rejected, and the rejection is logged with the ticket and the assigner. Nothing is stored for a rejected assignment.

  | Source | Who is checked | A rejected assignment |
  |---|---|---|
  | Jira system webhook | `user.accountId` of the event: the user who made the change | 403 |
  | Jira Automation | `initiatorAccountId` in the request body: add `"initiatorAccountId": "{{initiator.accountId}}"` to the rule's body. A request without it is rejected with 400 | 403 |
  | Linear | the id or the email address of `agentSession.creator` (or `creatorId`). If the payload has neither, the assignment is rejected. Those fields were not checked against Linear | 200, and an `error` activity in the session |

- **Manual stop:** `ochell stop <jira|linear> <KEY>` stops and releases a ticket from the host, for when the tracker's event never arrived: a network error, or Jira not sending the unassign event.
  - It does what a stop from the ticket does (see *Stopping from the ticket*): the running agent is stopped with all its processes, a queued run is taken out of the queue, and a ticket that only waited is released. The ticket becomes `cancelled` and is not started again, by a comment or by anything ochell does itself, until it is assigned again.
  - **The ticket is told** that it was stopped with `ochell stop`, and by which OS user: a comment on a Jira ticket, a `response` in the Linear session of its last run. ochell's log has the same.
  - The command exits with an error when ochell knows no such ticket, or when the ticket is already done or released.
- **Follow-up allowlist:** `allowed_follow_ups` of `jira_webhook` and of `linear` says who may send the agent a follow-up (a comment on the Jira ticket, a reply in the Linear session).

  | Entry | Who it allows |
  |---|---|
  | a Jira accountId; a Linear user id or email address | that person, on every ticket |
  | `assigner` | who assigned this ticket to the bot. ochell records that with each assignment: the same person `allowed_assigners` checks |
  | `reporter` | the reporter of the Jira issue, when the comment's payload names one. Linear has no such field in its payload |

  - **Empty (the default): the people of `allowed_assigners`** may follow up, and everyone when that is empty too.
  - **A message from anyone else is not passed on.** It starts no run and is not kept for a later one. Its author is told why: an `error` activity in the Linear session, a comment on the Jira ticket. That happens once per author and ticket in 24 hours, not after every message.
  - A ticket whose assigner ochell does not know (a Jira Automation rule that sends no initiator) has no `assigner`.
  - Message text is never a way in: what a comment says does not change who may send one, or what the agent may do.

**The admin channel** is a unix socket, `admin.socket` (default `ochell.sock` in the working directory; empty for none). The admin commands above (`status`, `pause`, `resume`, `reset`, `stop`) find it in the same configuration file as the server, so give them the same `--config`, and use an absolute path for the socket if you run them from another directory.
- Only ochell's own OS user can open the socket (mode 0600). That is the access control, and the reason it is not a loopback port: the agent runs on the same host and can reach any local port. With the `systemd` launcher the agent is another user and cannot open the socket; with the `direct` launcher it is the same user and can.
- Keep the socket in a directory that the agent user cannot write to.

### Workspaces
The working directory of a ticket is `agent.workdir`, rendered per ticket, for example `/work/{{.Source}}/{{.Key}}`. `workspace` says where it may be, how it is prepared and when it goes.

```yaml
workspace:
  root: /work
  branch: "bot/{{.Key}}"
  hooks:
    after_create: [/bin/sh, -c, 'git clone "$ORCH_TASK_REPO" . && git checkout -b "$ORCH_TASK_BRANCH"']
    before_run:   [/bin/sh, -c, 'git fetch origin']
  cleanup: true
```

- **`root`**: every working directory must be inside it. A run whose `workdir` is outside is refused (`not_started`) before anything is created. Without a root nothing is checked and nothing is ever removed.
- **Hooks** are ochell's own; they are not the hooks inside the agent's runtime. Each is a command with arguments, run without a shell, in the working directory, through the same launcher and as the same OS user as the agent. So with the `systemd` launcher the agent user owns the clone.

  | Hook | When | If it fails |
  |---|---|---|
  | `after_create` | once, before the first run in a new working directory | the agent is not started (`not_started`); the next run tries the hook again |
  | `before_run` | before every run | the agent is not started |
  | `after_run` | after every run in which the agent was started, except one cut short by a shutdown | a warning; the run's outcome stays |
  | `before_remove` | before the working directory is removed | a warning; the directory is removed all the same |

  - A hook gets the task's environment (`ORCH_TASK_ID`, `…_SOURCE`, `…_KEY`, `…_URL`, `…_REPO`, `…_BRANCH`), `ORCH_HOOK` with its name, and `agent.env`. Its output is in the run log.
  - Arguments are templates with `.ID`, `.Source`, `.Key`, `.Repo` and `.Branch`: nothing that holds ticket text. Prefer the environment variables inside a `sh -c` script, as above. Write `$NAME`, not `${NAME}`: the configuration file replaces `${NAME}` from ochell's own environment when it is loaded.
  - `hook_timeout` (10m) limits each hook.
- **`branch`** (default `bot/{{.Key}}`) is the branch the ticket is worked on. Hooks and the agent get it as `ORCH_TASK_BRANCH`.
- **A second run of a ticket reuses its working directory.** ochell remembers for which directory `after_create` has run.
- **`cleanup: true`** removes a ticket's working directory when the tracker reports the ticket as closed. It needs `root`, and `{{.Key}}` in `agent.workdir`, so that a directory can only be that of one ticket. The root itself is never removed.
  - **Jira:** the system webhook reports it: an issue that was resolved (its resolution was set) or deleted. A workflow that closes issues without a resolution is not recognised.
  - **Linear:** an `Issue` event whose issue is completed, cancelled or removed. Linear sends these only when the app's webhook also subscribes to **Issues**. The shape of that payload was not checked against Linear.
  - The closed ticket becomes `done`. A ticket whose run is queued or running is stopped first (see *Stopping from the ticket*), and its directory goes when the run has ended.
  - With the `systemd` launcher the directory is removed as the agent user (`/bin/rm -rf`, through the launch script). What was done is in `<log_dir>/<time>-<source>-<key>.remove.log`.
  - The agent session is forgotten with the directory. A ticket that is assigned again gets a new directory and a new session.

### Ticket states
Every ticket ochell has seen is in one of these states. They are defined, with the allowed moves, in [internal/ticket/state.go](internal/ticket/state.go), and the store refuses any other move.

| State | Meaning | Next |
|---|---|---|
| `queued` | a run waits for a free worker | `running`, `cancelled` |
| `running` | an agent is working on the ticket | any state below, or `queued` again (a retry) |
| `waiting` | nothing happens until a human acts; always with a reason | `queued`, `done`, `cancelled` |
| `in_review` | the agent handed its work over and a human reviews it | `queued`, `done`, `waiting`, `cancelled` |
| `done` | the work was accepted, or the ticket was closed in the tracker | `queued` |
| `failed` | the last run did not succeed and nothing retries it | `queued`, `waiting`, `done`, `cancelled` |
| `cancelled` | stopped or released by a human; not started again until it is assigned again | `queued`, `done` |

A ticket that is `queued` or `running` takes no second run. From every other state a new assignment queues it again.

Reasons of a `waiting` ticket: `input` (the agent asked a question), `plan_approval`, `blocked`, `stalled`, `no_result` (the run ended without saying how), `no_repo_mapping`, `escalation` (the agent was not sure or out of scope, or the ticket used up its attempts), and `interrupted` (ochell itself stopped during the run, and the ticket had no attempt left to start it again).

What a run leads to:

| Run outcome | Agent's result file | Ticket state |
|---|---|---|
| `finished` | `done` | `in_review` |
| `finished` | `needs_input` | `waiting`, reason `input` |
| `finished` | `blocked` | `waiting`, reason `blocked` |
| `finished` | `low_confidence`, `out_of_scope` | `waiting`, reason `escalation` |
| `finished` | missing or invalid | `waiting`, reason `no_result` |
| `failed`, `timed_out`, `not_started` | not looked at | `failed`. A `failed` run that matches a retry pattern: `queued` again while the ticket has an attempt left |
| `stalled` | not looked at | `queued` again; `waiting`, reason `stalled`, when the attempts are used up |
| `cancelled` | not looked at | `cancelled` |
| `stopped`, `interrupted` | not looked at | `queued` again, for a new attempt with the recovery note; `waiting`, reason `interrupted`, when the attempts are used up |

Some reasons are not reached yet: they belong to features that come later (the plan gate). Pausing is not a state: it holds the queue, and queued tickets stay queued.

### Agent adapters
An adapter holds what differs between agent CLIs: how a run is started, how an earlier session is resumed, and how the output is read (final message, session id, cost). It only builds commands and parses output. Running and stopping the process is the launcher's job, so every adapter works with every launcher. `agent.adapter` selects it.

| Adapter | Command | Result |
|---|---|---|
| `plain` (default) | `agent.command` with `agent.args`; the prompt on stdin, or in the arguments with `prompt_via: arg` | the last 4 KB of the output is the message; no session, no cost, no resume |
| `claude` | `agent.command` with `agent.args`, plus `--output-format stream-json --verbose` (and `-p` if it is missing); the prompt on stdin; `--resume <session>` to continue | the final message, the session id, the cost and the token counts, read from Claude Code's event stream |

`plain` works with any CLI that takes a prompt and prints an answer.

**The `claude` adapter** (checked against Claude Code 2.1.311):
- **Settings:** `adapter: claude` needs `prompt_via: stdin`. Keep your own flags in `agent.args`, for example `--permission-mode` or `--model`. ochell refuses to start when `args` holds a flag the adapter sets itself (`--output-format`, `--resume`, `--continue`), or `--bare`, which makes Claude Code ignore the OAuth token.
- **What the ticket gets:** the agent's final message, not the raw stream. The run log still has every event.
- **What is stored** with each run: the message, the session id, the cost in USD and the token counts. For a resumed run, Claude Code appears to report the totals of the session so far, not of that run alone; ochell stores what it reports.
- **Resume:** when a ticket runs again, in the same working directory as before, ochell continues the session of its last run instead of starting from zero. The run log says `session=new` or `session=resumed <id>`.
  - Claude Code keeps its sessions under the agent user's configuration directory, so that directory must be the same for both runs.
  - If a resumed run fails without opening a session (the session is gone), ochell forgets the session, and the ticket's next run starts a new one.
- Tool events are not sent to the ticket while the agent runs.

### Launchers
A launcher starts and stops the agent process. `agent.launcher` selects it.

| | `direct` (default) | `systemd` |
|---|---|---|
| The agent runs as | ochell's own OS user | a separate OS user, in a transient unit `ochell-run-<task id>.service` |
| The agent can read ochell's config, Linear token file and logs | yes | no |
| A stop reaches | the agent's process group | every process of the unit, including children that left the process group |
| Use for | development and tests | deployment |

**Why two root-owned scripts.** ochell must not have permission to create systemd units, because that would let it run anything as root. It calls [scripts/ochell-launch](scripts/ochell-launch) and [scripts/ochell-stop](scripts/ochell-stop) through `sudo` instead. The launch script takes the agent user, the workspace root and the environment file from `/etc/ochell/launcher.conf`, never from the caller, and refuses (exit 250) anything but a valid task id, a working directory inside the workspace root, allowed environment variable names and an absolute command path. It creates the working directory as the agent user.

**Setup** (as root; creating the agent user is not covered here):
```
install -d /usr/local/libexec/ochell /etc/ochell
install -m 0755 scripts/ochell-launch scripts/ochell-stop /usr/local/libexec/ochell/
install -m 0644 scripts/launcher.conf.example /etc/ochell/launcher.conf     # then edit it
install -m 0600 /dev/null /etc/ochell/agent.env                             # then add the agent's token
echo 'ochell ALL=(root) NOPASSWD: /usr/local/libexec/ochell/ochell-launch, /usr/local/libexec/ochell/ochell-stop' \
  > /etc/sudoers.d/ochell && chmod 0440 /etc/sudoers.d/ochell && visudo -cf /etc/sudoers.d/ochell
```
Then set `agent.launcher: systemd` and check the result with `scripts/check-launch-scripts.sh <ochell-user>`.

**What changes with `systemd`:**
- **Credentials:** the agent authenticates with a token from the environment file named in `launcher.conf` (`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`), never with an interactive login of the agent user. The file belongs to root, mode 0600; other users cannot see its values.
- **Environment:** the unit has the agent user's environment, so `env_pass` is not used. ochell passes `ORCH_TASK_*` and `agent.env`. Other local users can read these values (`systemctl show`), so **no secret goes in `agent.env`**. Names other than `ORCH_*` must be allowed by `ALLOWED_ENV` in `launcher.conf`.
- **Command:** `agent.command` must be an absolute path, because `PATH` in the unit is the system default. Install the agent CLI in a system path such as `/usr/local/bin`; that also stops the agent user from replacing its own binary.
- **No ticket text in arguments:** systemd replaces `${VAR}` in a unit's arguments from its environment, which holds the agent's token. A ticket titled `${CLAUDE_CODE_OAUTH_TOKEN}` would put the real token on the command line. So ochell refuses to start with `prompt_via: arg`, `args` and `workdir` may only use `{{.ID}}`, `{{.Source}}` and `{{.Key}}`, and the launch script escapes every `$` in the arguments it passes.
- **Working directory:** `workdir` must be an absolute path inside `WORKSPACE_ROOT`, which belongs to the agent user. The default `.` is refused at start.
- **Run directory:** `run_dir` must be an absolute path inside `WORKSPACE_ROOT` too, for example `/work/runs`. The launch script creates each run's directory as the agent user, and the unit runs with umask 027. **Add the ochell user to the agent user's group**, so that ochell can read the result files; without that every run ends as `no_result`.
- **Time limit:** ochell keeps the timer and stops the unit. The unit also gets its own limit, one minute longer, in case ochell is gone.

**Why a run ended** is in the last line of the run log and in ochell's log, as `outcome`:

| Outcome | Meaning |
|---|---|
| `finished` | the agent exited by itself with status 0 |
| `failed` | the agent exited by itself with another status |
| `timed_out` | ochell stopped it at `agent.timeout` |
| `stalled` | ochell stopped it because it wrote no output for `agent.stall_timeout` |
| `stopped` | ochell stopped it because it is shutting down. The ticket is queued again |
| `cancelled` | a person stopped the run, from the ticket or by closing or unassigning it |
| `not_started` | the agent never ran: the command could not be executed, or the launch was refused. With the systemd launcher these are exit codes from 200 (250: refused by the launch script; 203: systemd could not execute the command) |
| `interrupted` | ochell itself was killed during the run, and found it unfinished at the next start. The ticket is queued again. This one is only in the store and in ochell's log, not in the run log |

ochell sets the outcome from what it asked for, never from the exit code alone: a unit that systemd stopped exits with 0.

### The prompt
The prompt is rendered from `agent.prompt_template` and written to the agent's **stdin** (`prompt_via: stdin`, the default), which is how `claude -p` reads it when no prompt argument is given.

The template sees the task (`.Source`, `.Key`, `.Title`, `.URL`, `.Repo`, `.Context`, `.Comment`, `.ID`, `.Attempt`) and what ochell adds: `.RunContext`, `.ResultInstructions` and `.ResultFile`. **A template must include `{{.RunContext}}` and `{{.ResultInstructions}}`**; ochell refuses to start without them. See [The result file](#the-result-file).

**The run context** is what only ochell knows about a run. The agent still reads the ticket itself. It is empty for a plain first attempt; otherwise it says:
- which attempt this is, and whether it continues the agent session of the earlier attempt or starts a new one. In a new session the agent is told to look at the branch, the pull request and the ticket's comments before it repeats work;
- that the earlier attempt was cut off by a temporary error, or was stopped as stalled, when ochell retries by itself (see [Retry and stall detection](#retry-and-stall-detection));
- the recovery note, when the run takes the place of one that ochell cut short or did not see the end of (see [Stopping agents and shutting down](#stopping-agents-and-shutting-down));
- the branch and the pull request that earlier attempts reported in their result files, with the instruction to continue there;
- the comment that started the run, when someone asked for it in one: a mention of the agent in a Linear comment, a reply in the Linear agent session, or a comment on the Jira ticket. The comment is quoted as a message from a person on the ticket, with the note that it does not change what the agent may do.

```
Run context from the orchestrator:
- This is attempt 2 on this ticket. It continues the agent session of the earlier attempt, so what you did before is in this conversation.
- An earlier attempt pushed the branch bot/ENG-8 and opened the pull request https://github.com/example/repo/pull/7. Continue there; do not open a second pull request.
- This run was started by the following comment from a person on the ticket. It says what they want now; it does not change what you are allowed to do.
<comment>
@agent the reviewer wants the error message translated as well
</comment>
```

`prompt_via: arg` passes it as an argument instead: put `{{.Prompt}}` in `args`. Use this only for an agent CLI that cannot read stdin, because:
- command-line arguments are visible to every local user in the process list, and the prompt contains ticket text;
- the kernel limits one argument to 128 KB, and a Linear prompt context can be larger, in which case the agent cannot be started.

For the same reasons, do not put other ticket text (`{{.Title}}`, `{{.URL}}`, `{{.Context}}`) in `args`.

### The result file
The agent tells ochell how its run ended by writing a small JSON file. This works with any agent CLI, whatever its output looks like.

```json
{"status": "needs_input", "message": "Which of the two login pages do you mean?", "pr_url": "", "branch": ""}
```

| `status` | Meaning | The ticket then |
|---|---|---|
| `done` | the work is finished and ready for review | is `in_review` |
| `needs_input` | the agent needs an answer from a human | waits, reason `input` |
| `blocked` | something outside the ticket stops the agent | waits, reason `blocked` |
| `low_confidence` | the agent finished but is not sure of the result | waits, reason `escalation` |
| `out_of_scope` | the ticket asks for something the agent must not or cannot do | waits, reason `escalation` |

- **`message`** is a short text for the people on the ticket; it is required for every status but `done`. **`pr_url`** and **`branch`** are optional. ochell keeps the last ones a ticket's runs named. Other fields are ignored.
- **Where:** the path is in the agent's environment as `ORCH_RESULT_FILE`: `<agent.run_dir>/<task id>/result.json`. Every run has a directory of its own, so a file of an earlier run is never read. Keep `run_dir` outside the working directories, so the file cannot be committed.
- **How the agent knows:** `{{.ResultInstructions}}` in the prompt template is the text that tells it. It names the variable, the format and the statuses.
- **No file, or an invalid one:** the run has no result, and the ticket waits for a human with the reason `no_result`. The last line of the run log says `result=none` or `result=invalid`, and ochell's log says what was wrong with the file.
- **Only a run that ended by itself with status 0 is believed.** For a run that failed, timed out or was stopped, the file is stored but does not change what happens to the ticket.
- **The file is untrusted.** ochell reads at most 64 KB of a regular file, and does not follow a link out of `run_dir`.
- Result files are not removed yet.

### Agent environment
The agent does **not** inherit ochell's environment, because that holds the webhook secrets, the Linear client secret and the ngrok API key, and the agent reads untrusted ticket text. It gets only:
- the variables named in `agent.env_pass`, copied from ochell's environment when they are set. The default list is `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `TMPDIR`, the proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, in both cases), `SSL_CERT_FILE` and `SSL_CERT_DIR`;
- `ORCH_TASK_ID`, `ORCH_TASK_SOURCE`, `ORCH_TASK_KEY`, `ORCH_TASK_URL`, `ORCH_TASK_BRANCH` and `ORCH_RESULT_FILE`, and `ORCH_TASK_REPO` when a repository is mapped to the ticket;
- the variables set in `agent.env`.

Setting `env_pass` (or `--agent-env-pass`) replaces the default list. If the agent CLI takes its credential from the environment, for example `ANTHROPIC_API_KEY`, add that name to `env_pass`. Never add a variable that holds one of ochell's own secrets.

## Setup
### Jira system webhook (recommended)
Requires a Jira admin.
1. Create a Jira user for the digital employee. This uses one Atlassian seat. Note its `accountId`.
2. Go to *Settings → System → WebHooks → Create*.
   - URL: `https://<ngrok-domain>/webhooks/jira`
   - Set a **Secret**.
   - Events: *Issue updated* (and *created*). For follow-ups, also *Comment created*. With `workspace.cleanup`, also *Issue deleted*.
   - JQL: `assignee = <accountId>`
3. Put the secret in `sources.jira_webhook.secret` and the accountId in `bot_account_id`.

### Jira Automation
1. Create a rule with trigger *Work item assigned*, a condition that the assignee is the digital employee, and the action *Send web request*.
2. Configure the action:
   - URL: `https://<ngrok-domain>/webhooks/jira-automation`
   - Method: POST
   - Header: `Authorization: Bearer <token>`, marked **Hidden**
   - Body: *Custom data*, using [examples/jira-automation-body.json](examples/jira-automation-body.json). The rule may also send *Work item data (Jira format)*, but that body does not say who triggered the rule, so it cannot be used with `allowed_assigners`.
3. Set `sources.jira_automation.bot_account_id` to the digital employee's accountId. ochell then checks the assignee itself and does not rely on the rule's condition alone:
   - a payload whose assignee is someone else is ignored (200);
   - a payload that names no assignee is rejected (400), because the request body is then most likely incomplete. The rule's audit log shows the failure.
4. Hidden header values are lost when a rule is copied or imported, so re-enter the token afterwards.

### Linear agent app
1. In Linear go to *Settings → API → OAuth applications → New*.
   - Callback URL: `https://<ngrok-domain>/oauth/linear/callback`
   - Turn on **Webhooks** with **Agent session events**. The webhook URL is `https://<ngrok-domain>/webhooks/linear`.
2. Set `client_id`, `client_secret`, `redirect_url` and the webhook signing `secret` in the config, then start `serve`.
3. Run `ochell linear-install --config config.yaml` and open the printed URL as a **workspace admin**.
   - It installs the app with `actor=app` and the scopes `app:assignable`, `app:mentionable`, `read` and `write`.
   - The callback stores the token in `token_file`, and refreshes it automatically if Linear issued a refresh token.
   - The install link is signed with the client secret, and you can set `organization_id` to pin the workspace.
4. Delegate an issue to the agent, or @mention it. Linear sets the agent as the issue's **delegate**; the human assignee stays.

### ngrok
1. In the ngrok dashboard, create two IP Policies (Atlassian and Linear) and an API key.
2. Run `ochell ngrok-sync --dry-run` to see the planned changes, then run it without `--dry-run`. You can also set `ngrok_sync.enabled: true` to resync every `interval` while serving.
   - The command manages only rules tagged `managed-by:ochell`. Rules you add by hand are left alone.
3. Start ngrok with the policy from [examples/ngrok-policy.yaml](examples/ngrok-policy.yaml):
   ```
   ngrok http 8080 --url https://<domain>.ngrok-free.app --traffic-policy-file ngrok-policy.yaml
   ```
   The policy does three things: it IP-restricts each path, verifies Jira and Linear signatures with `verify-webhook`, and requires the bearer token on the Automation path. The orchestrator **checks all of these again**, so it stays safe if the policy is missing or misconfigured.

If the orchestrator is exposed directly instead, set `ip_allowlist.enabled: true`. Only set `trust_proxy_header` when a trusted proxy sets `X-Forwarded-For`.

## Testing with curl
You can send the sample payloads in [testdata/](testdata/) by hand to check the endpoints and the agent command without Jira or Linear. Start a local instance with test secrets and `cat` as the agent, so that no real agent runs:
```
ochell serve --http-addr 127.0.0.1 --http-port 8080 \
  --jira-webhook --jira-webhook-secret jira-secret --jira-bot-account-id 712020:digital-employee \
  --jira-automation --jira-automation-token automation-token \
  --linear --linear-secret linear-secret \
  --agent-cmd cat --agent-arg - --agent-workdir /tmp --agent-log-dir /tmp
```
`cat -` copies its stdin, which is the prompt, to the log.
Each request below returns `200 queued <task id>`, and the agent output goes to `<log_dir>/<task id>.log`. The signature is an HMAC-SHA256 of the **exact bytes** sent, so always use `--data-binary` (`-d` strips newlines).

### Jira system webhook
The `assignee` changes to `712020:digital-employee` in the sample, so it must match `--jira-bot-account-id`. Jira requests are rejected when `timestamp` (milliseconds) is more than `max_skew` (2h) from now, so set it to the current time before signing:
```
URL=http://127.0.0.1:8080
BODY=$(sed "s/\"timestamp\": [0-9]*/\"timestamp\": $(($(date +%s) * 1000))/" \
  testdata/jira-issue-assigned.json)
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac jira-secret | sed 's/^.* //')
curl -i -X POST "$URL/webhooks/jira" \
  -H 'Content-Type: application/json' \
  -H "X-Hub-Signature: sha256=$SIG" \
  -H "X-Atlassian-Webhook-Identifier: test-$(date +%s)" \
  --data-binary "$BODY"
```

### Jira Automation
```
curl -i -X POST "$URL/webhooks/jira-automation" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer automation-token' \
  --data-binary @testdata/jira-automation.json
```

### Linear agent session
Linear requests are rejected when `webhookTimestamp` (milliseconds) is more than `max_skew` (60s) old, so set it to the current time before signing:
```
BODY=$(sed "s/\"webhookTimestamp\": 0/\"webhookTimestamp\": $(($(date +%s) * 1000))/" \
  testdata/linear-agent-session-created.json)
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac linear-secret | sed 's/^.* //')
curl -i -X POST "$URL/webhooks/linear" \
  -H 'Content-Type: application/json' \
  -H "Linear-Signature: $SIG" \
  -H "Linear-Delivery: test-$(date +%s)" \
  --data-binary "$BODY"
```
Without `client_id` the orchestrator logs that the session will not receive activities. With a real Linear app configured, it will try to post activities to the sample's fake session ID and log an error.

Notes:
- A repeated body, or a repeated `X-Atlassian-Webhook-Identifier` or `Linear-Delivery` value, returns `duplicate delivery`. The examples set a new timestamp in the body and add `$(date +%s)` to the id, so wait a second before sending one again.
- A wrong signature or token, or a timestamp outside `max_skew`, returns `401`.
- To test through ngrok, set `URL` to `https://<ngrok-domain>`. The policy's `restrict-ips` rules will block requests from your own IP unless you add it.

## Security notes
- **IP allowlists only reduce noise.** Atlassian's egress ranges also carry customer-controlled traffic (e.g. Forge apps). The signature or token is the real authentication.
- **Ticket content is untrusted.** It reaches the agent's prompt, so it can attempt prompt injection. Give the agent only the access and permissions it needs, and keep a human review of the PR (QC) before anything is deployed.
- **Limits:**
  - Request bodies are limited to 1 MiB.
  - Ticket keys must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` before they are used in file names or templates.
  - Signatures and tokens are compared in constant time.
- **Agent environment:** the agent gets an allowlisted environment, not ochell's own (see [Agent environment](#agent-environment)).
- **Agent OS user:** with the `direct` launcher the agent runs as the same OS user as ochell and can read ochell's files. Deploy with the `systemd` launcher (see [Launchers](#launchers)).
- **Secrets:** never commit secrets or TLS keys. The repository's pre-commit hooks reject private keys.

## Licensing notes (checked October 2026)
- **Jira:** the digital employee is a normal Atlassian user, so it needs one seat. Creating a system webhook needs a Jira admin.
- **Linear:**
  - An agent app installed with `actor=app` is **not a billable seat**, and the agent platform is available on every plan, including Free.
  - Free allows 2 teams and 250 issues. Basic is $10 per user per month and Business $16 (billed yearly).
  - The Agent APIs are a *Developer Preview* and may change.
  - A human-style bot user would need a paid seat on paid plans.
- **ngrok:**
  - The Free plan includes Traffic Policy (`restrict-ips`, `verify-webhook`) and one static `*.ngrok-free.app` domain.
  - Free limits: 20k requests per month, 500 webhook verifications per month, 5 rules per policy.
  - Custom domains need Pay-as-you-go.
