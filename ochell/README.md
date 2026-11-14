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
| Jira system webhook | `POST /webhooks/jira` | `X-Hub-Signature: sha256=<HMAC>` with the webhook secret, and `timestamp` within `max_skew` (2h) | `jira:issue_updated` whose changelog changes `assignee` to the bot, or `jira:issue_created` already assigned to the bot |
| Jira Automation "Send web request" | `POST /webhooks/jira-automation` | Shared token in a header (`Authorization: Bearer …` by default). Automation cannot sign payloads. | An authenticated request that names the bot as assignee. Without `bot_account_id`, any authenticated request (the rule decides when to fire) |
| Linear agent app (`actor=app`) | `POST /webhooks/linear` | `Linear-Signature` HMAC and `webhookTimestamp` within 60s | `AgentSessionEvent` `created` (issue delegated to, or agent mentioned) |

Behaviour common to all sources:
- **Responses:**
  - 200 when a task is queued, ignored or a duplicate;
  - 401 when authentication fails;
  - 400 when the payload is unusable, for example a Jira Automation request that names no assignee;
- **Duplicate deliveries:** a signed request is dropped when its body, or its `X-Atlassian-Webhook-Identifier` / `Linear-Delivery` id, was seen before. The body counts because the signature covers it; the id is a header that a replayed request can change. Both are kept in the store for 24 hours, also across a restart.
- **Replay:** a signed request is rejected with 401 when its timestamp (`timestamp` for Jira, `webhookTimestamp` for Linear) is further than `max_skew` from now. The default is 60s for Linear and 2h for Jira: Jira retries a failed delivery up to five times, 5 to 15 minutes apart, and a retry may carry the timestamp of the event. Jira Automation requests carry no timestamp.
- **One run per ticket:** a ticket that is already queued or running is not started again. The request is answered with 200 `already in progress`. A new Linear session on such a ticket gets a `response` activity that says so, which closes that session; the result is posted in the first session.
- **Linear session updates:** the orchestrator posts a `thought` activity right away, because Linear expects one within 10s. When the run ends it posts what the agent reported in its result file (see [The result file](#the-result-file)): a `response` for finished work, an `elicitation` for anything that needs a human. A run that failed, timed out or was stopped gets an `error`.
- **Linear follow-ups:** `prompted` events are logged but not yet delivered to an agent. So a reply to an `elicitation` does not start a run yet; delegate the ticket again.

### Stopping agents and shutting down
- **A stop ends the whole agent**, not only its top process: sub-agents, MCP servers and git children too. ochell sends SIGTERM, and SIGKILL after `agent.stop_grace` (10s). This happens at `agent.timeout` and on shutdown.
  - With the `systemd` launcher ochell stops the unit, and systemd signals every process in it.
  - With the `direct` launcher the agent runs in its own process group and ochell signals the group. A child that leaves the group (`setsid`) is not reached; use the `systemd` launcher where that matters. When the agent exits by itself, what it left running in its group is killed as well.
- **Shutdown** (SIGTERM or Ctrl-C): ochell stops accepting webhooks and waits up to `agent.drain_timeout` (30s) for running agents to finish. Then it stops the ones still running; their tickets get an error that says so. A second signal ends the wait at once. Tasks that were queued but not started stay in the store and run after the next start.
  - If ochell runs as a systemd service, set the service's `TimeoutStopSec` above `drain_timeout` plus `stop_grace`, or systemd kills ochell first.
  - Interrupted runs are not resumed after a restart.
- **After a crash** (ochell was killed, or the host went down): at the next start, queued tasks run as usual. A run that was in progress is closed as `interrupted`, its ticket gets an error that says so, and it is not started again. ochell does not look for an agent that such a run may have left behind.

## Build
```
make test                 # go vet + go test -race
make                      # cross-compile for linux/darwin/windows on amd64/arm64
go build -o ochell .
```

### End-to-end tests
`go test ./e2e/` (part of `make test`) starts a real `ochell` process and sends it signed webhooks. The agent is [e2e/fakeagent](e2e/fakeagent/main.go), a scripted stand-in that records its arguments, environment, stdin and working directory, and Linear is a fake API that records the activities ochell posts. No real agent or tracker is involved.

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
ochell version
```

## Configuration
Configuration comes from YAML and/or flags. Precedence is **defaults < YAML < flags**, and a flag only overrides YAML when it is given. `${VAR}` in YAML is replaced from the environment, so secrets can stay out of the file. See [examples/config.yaml](examples/config.yaml) for every option.

Common flags (run `ochell serve -h` for all of them):

| Flag | Meaning |
|---|---|
| `--http`, `--http-addr`, `--http-port` | Enable the HTTP listener and set its address and port separately |
| `--https`, `--https-addr`, `--https-port`, `--tls-cert`, `--tls-key` | Same for HTTPS (TLS 1.2+) |
| `--store-path` | File that holds the tickets, the task queue and the handled deliveries (default `ochell.db`); see [The store](#the-store) |
| `--agent-cmd` | Agent CLI executable (default `claude`) |
| `--agent-arg` | Agent argument; repeatable; replaces the YAML `args` (default `-p`). Go template: `{{.Key}}`, `{{.Source}}`, `{{.ID}}`. Keep ticket text (`{{.Title}}`, `{{.URL}}`, `{{.Context}}`, `{{.Prompt}}`) out of arguments; see [The prompt](#the-prompt) |
| `--agent-prompt-via` | `stdin` (default) or `arg` |
| `--agent-adapter` | Kind of agent CLI: `plain` (default) or `claude`; see [Agent adapters](#agent-adapters) |
| `--agent-launcher` | `direct` (default) or `systemd`; see [Launchers](#launchers) |
| `--agent-env-pass` | Variable the agent inherits from ochell's environment; repeatable; replaces the default list (see [Agent environment](#agent-environment)) |
| `--agent-workdir`, `--agent-timeout`, `--agent-max-concurrent`, `--agent-log-dir`, `--agent-run-dir` | Execution settings |
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

### Ticket states
Every ticket ochell has seen is in one of these states. They are defined, with the allowed moves, in [internal/ticket/state.go](internal/ticket/state.go), and the store refuses any other move.

| State | Meaning | Next |
|---|---|---|
| `queued` | a run waits for a free worker | `running`, `cancelled` |
| `running` | an agent is working on the ticket | any state below, or `queued` again (a retry) |
| `waiting` | nothing happens until a human acts; always with a reason | `queued`, `done`, `cancelled` |
| `in_review` | the agent handed its work over and a human reviews it | `queued`, `done`, `waiting`, `cancelled` |
| `done` | the work was accepted, or the ticket was closed | `queued` |
| `failed` | the last run did not succeed and nothing retries it | `queued`, `waiting`, `cancelled` |
| `cancelled` | stopped or released by a human; not started again until it is assigned again | `queued` |

A ticket that is `queued` or `running` takes no second run. From every other state a new assignment queues it again.

Reasons of a `waiting` ticket: `input` (the agent asked a question), `plan_approval`, `blocked`, `stalled`, `no_result` (the run ended without saying how), `no_repo_mapping`, `escalation`, and `interrupted` (ochell itself stopped during the run).

What a run leads to:

| Run outcome | Agent's result file | Ticket state |
|---|---|---|
| `finished` | `done` | `in_review` |
| `finished` | `needs_input` | `waiting`, reason `input` |
| `finished` | `blocked` | `waiting`, reason `blocked` |
| `finished` | `low_confidence`, `out_of_scope` | `waiting`, reason `escalation` |
| `finished` | missing or invalid | `waiting`, reason `no_result` |
| `failed`, `timed_out`, `not_started` | not looked at | `failed` |
| `stopped`, `interrupted` | not looked at | `waiting`, reason `interrupted` |

Several states and reasons are not reached yet: they belong to features that come later (the plan gate, stop from the ticket, handoff). Pausing will not be a state: it holds the queue, and queued tickets stay queued.

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
| `stopped` | ochell stopped it because it is shutting down |
| `not_started` | the agent never ran: the command could not be executed, or the launch was refused. With the systemd launcher these are exit codes from 200 (250: refused by the launch script; 203: systemd could not execute the command) |
| `interrupted` | ochell itself was killed during the run, and found it unfinished at the next start. This one is only in the store and in ochell's log, not in the run log |

ochell sets the outcome from what it asked for, never from the exit code alone: a unit that systemd stopped exits with 0.

### The prompt
The prompt is rendered from `agent.prompt_template` and written to the agent's **stdin** (`prompt_via: stdin`, the default), which is how `claude -p` reads it when no prompt argument is given.

The template sees the task (`.Source`, `.Key`, `.Title`, `.URL`, `.Context`, `.ID`, `.Attempt`) and two things ochell adds: `.ResultInstructions` and `.ResultFile`. **A template must include `{{.ResultInstructions}}`**; ochell refuses to start without it. See [The result file](#the-result-file).

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
- `ORCH_TASK_ID`, `ORCH_TASK_SOURCE`, `ORCH_TASK_KEY`, `ORCH_TASK_URL` and `ORCH_RESULT_FILE`;
- the variables set in `agent.env`.

Setting `env_pass` (or `--agent-env-pass`) replaces the default list. If the agent CLI takes its credential from the environment, for example `ANTHROPIC_API_KEY`, add that name to `env_pass`. Never add a variable that holds one of ochell's own secrets.

## Setup
### Jira system webhook (recommended)
Requires a Jira admin.
1. Create a Jira user for the digital employee. This uses one Atlassian seat. Note its `accountId`.
2. Go to *Settings → System → WebHooks → Create*.
   - URL: `https://<ngrok-domain>/webhooks/jira`
   - Set a **Secret**.
   - Event: *Issue updated* (and *created*).
   - JQL: `assignee = <accountId>`
3. Put the secret in `sources.jira_webhook.secret` and the accountId in `bot_account_id`.

### Jira Automation
1. Create a rule with trigger *Work item assigned*, a condition that the assignee is the digital employee, and the action *Send web request*.
2. Configure the action:
   - URL: `https://<ngrok-domain>/webhooks/jira-automation`
   - Method: POST
   - Header: `Authorization: Bearer <token>`, marked **Hidden**
   - Body: *Custom data*, using [examples/jira-automation-body.json](examples/jira-automation-body.json). The rule may also send *Work item data (Jira format)*.
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
