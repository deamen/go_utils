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
| Jira system webhook | `POST /webhooks/jira` | `X-Hub-Signature: sha256=<HMAC>` with the webhook secret | `jira:issue_updated` whose changelog changes `assignee` to the bot, or `jira:issue_created` already assigned to the bot |
| Jira Automation "Send web request" | `POST /webhooks/jira-automation` | Shared token in a header (`Authorization: Bearer …` by default). Automation cannot sign payloads. | Any authenticated request (the rule decides when to fire) |
| Linear agent app (`actor=app`) | `POST /webhooks/linear` | `Linear-Signature` HMAC and `webhookTimestamp` within 60s | `AgentSessionEvent` `created` (issue delegated to, or agent mentioned) |

Behaviour common to all sources:
- **Responses:**
  - 200 when a task is queued, ignored or a duplicate;
  - 401 when authentication fails;
- **Duplicate deliveries:** dropped using `X-Atlassian-Webhook-Identifier` / `Linear-Delivery`.
- **One run per ticket:** a ticket that is already queued or running is not started again.
- **Linear session updates:** the orchestrator posts a `thought` activity right away, because Linear expects one within 10s. When the agent exits it posts a `response` (the tail of the agent output) or an `error`.
- **Linear follow-ups:** `prompted` events are logged but not yet delivered to a running agent.

## Build
```
make test                 # go vet + go test -race
make                      # cross-compile for linux/darwin/windows on amd64/arm64
go build -o ochell .
```

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
| `--agent-cmd` | Agent CLI executable (default `claude`) |
| `--agent-arg` | Agent argument; repeatable; replaces the YAML `args`. Go template: `{{.Prompt}}`, `{{.Key}}`, `{{.URL}}`, `{{.Source}}`, `{{.Title}}`, `{{.ID}}`, `{{.Context}}` |
| `--agent-prompt-via` | `arg` (default) or `stdin` |
| `--agent-env-pass` | Variable the agent inherits from ochell's environment; repeatable; replaces the default list (see [Agent environment](#agent-environment)) |
| `--agent-workdir`, `--agent-timeout`, `--agent-max-concurrent`, `--agent-log-dir` | Execution settings |
| `--jira-webhook`, `--jira-webhook-secret`, `--jira-bot-account-id` | Jira system webhook source |
| `--jira-automation`, `--jira-automation-header`, `--jira-automation-token` | Jira Automation source |
| `--linear`, `--linear-secret`, `--linear-client-id`, `--linear-client-secret`, `--linear-redirect-url` | Linear agent source |

Example without a YAML file:
```
JIRA_SECRET=... ochell serve --http-addr 127.0.0.1 --http-port 8080 \
  --jira-webhook --jira-webhook-secret "$JIRA_SECRET" --jira-bot-account-id 712020:... \
  --agent-cmd claude --agent-arg -p --agent-arg '{{.Prompt}}'
```

The agent runs without a shell, with its working directory set to `workdir` (rendered per task). Output goes to `<log_dir>/<task id>.log`.

### Agent environment
The agent does **not** inherit ochell's environment, because that holds the webhook secrets, the Linear client secret and the ngrok API key, and the agent reads untrusted ticket text. It gets only:
- the variables named in `agent.env_pass`, copied from ochell's environment when they are set. The default list is `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `TMPDIR`, the proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, in both cases), `SSL_CERT_FILE` and `SSL_CERT_DIR`;
- `ORCH_TASK_ID`, `ORCH_TASK_SOURCE`, `ORCH_TASK_KEY` and `ORCH_TASK_URL`;
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
3. Hidden header values are lost when a rule is copied or imported, so re-enter the token afterwards.

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
You can send the sample payloads in [testdata/](testdata/) by hand to check the endpoints and the agent command without Jira or Linear. Start a local instance with test secrets and `echo` as the agent, so that no real agent runs:
```
ochell serve --http-addr 127.0.0.1 --http-port 8080 \
  --jira-webhook --jira-webhook-secret jira-secret --jira-bot-account-id 712020:digital-employee \
  --jira-automation --jira-automation-token automation-token \
  --linear --linear-secret linear-secret \
  --agent-cmd echo --agent-arg '{{.Prompt}}' --agent-workdir /tmp --agent-log-dir /tmp
```
Each request below returns `200 queued <task id>`, and the agent output goes to `<log_dir>/<task id>.log`. The signature is an HMAC-SHA256 of the **exact bytes** sent, so always use `--data-binary` (`-d` strips newlines).

### Jira system webhook
The `assignee` changes to `712020:digital-employee` in the sample, so it must match `--jira-bot-account-id`.
```
URL=http://127.0.0.1:8080
BODY=testdata/jira-issue-assigned.json
SIG=$(openssl dgst -sha256 -hmac jira-secret < "$BODY" | sed 's/^.* //')
curl -i -X POST "$URL/webhooks/jira" \
  -H 'Content-Type: application/json' \
  -H "X-Hub-Signature: sha256=$SIG" \
  -H "X-Atlassian-Webhook-Identifier: test-$(date +%s)" \
  --data-binary @"$BODY"
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
- A repeated `X-Atlassian-Webhook-Identifier` or `Linear-Delivery` value returns `duplicate delivery`, which is why the examples add `$(date +%s)`.
- A wrong signature or token returns `401`.
- To test through ngrok, set `URL` to `https://<ngrok-domain>`. The policy's `restrict-ips` rules will block requests from your own IP unless you add it.

## Security notes
- **IP allowlists only reduce noise.** Atlassian's egress ranges also carry customer-controlled traffic (e.g. Forge apps). The signature or token is the real authentication.
- **Ticket content is untrusted.** It reaches the agent's prompt, so it can attempt prompt injection. Give the agent only the access and permissions it needs, and keep a human review of the PR (QC) before anything is deployed.
- **Limits:**
  - Request bodies are limited to 1 MiB.
  - Ticket keys must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` before they are used in file names or templates.
  - Signatures and tokens are compared in constant time.
- **Agent environment:** the agent gets an allowlisted environment, not ochell's own (see [Agent environment](#agent-environment)). It still runs as the same OS user as ochell, so it can read ochell's files.
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
