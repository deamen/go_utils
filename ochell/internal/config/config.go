// Package config loads the orchestrator configuration.
//
// Precedence: built-in defaults < YAML file (--config) < command line flags.
// Flags are bound directly to the struct after the YAML file has been loaded,
// so a flag only overrides the YAML value when it is explicitly set.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Listener struct {
	Enabled  bool   `yaml:"enabled"`
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

func (l Listener) Addr() string {
	return fmt.Sprintf("%s:%d", l.Address, l.Port)
}

type Agent struct {
	// Command is the agent CLI executable, e.g. "claude".
	Command string `yaml:"command"`
	// Args are passed to Command without a shell. Each arg is a Go
	// text/template rendered with the task (e.g. "{{.Key}}").
	Args []string `yaml:"args"`
	// PromptVia is "stdin" (the default) or "arg" (the prompt is referenced
	// in Args as {{.Prompt}}). As an argument the prompt is visible in the
	// process list and limited to 128 KB by the kernel.
	PromptVia      string `yaml:"prompt_via"`
	PromptTemplate string `yaml:"prompt_template"`
	Workdir        string `yaml:"workdir"`
	// Adapter names the kind of agent CLI: how it is called and how its
	// output is read. "plain" works with any CLI; "claude" is Claude Code
	// with its event stream, which gives the session id and the cost.
	Adapter string `yaml:"adapter"`
	// Launcher is "direct" (the agent is a child process of ochell) or
	// "systemd" (a transient unit under a separate OS user).
	Launcher string  `yaml:"launcher"`
	Systemd  Systemd `yaml:"systemd"`
	// StopGrace is how long an agent that is being stopped has between
	// SIGTERM and SIGKILL.
	StopGrace time.Duration `yaml:"stop_grace"`
	// DrainTimeout is how long a shutdown waits for running agents to
	// finish before it stops them.
	DrainTimeout time.Duration `yaml:"drain_timeout"`
	// EnvPass names the variables the agent inherits from ochell's own
	// environment. Everything else, including ochell's secrets, is dropped.
	EnvPass []string `yaml:"env_pass"`
	// Env is set for the agent in addition to EnvPass and ORCH_TASK_*.
	Env     map[string]string `yaml:"env"`
	Timeout time.Duration     `yaml:"timeout"`
	// StallTimeout is how long an agent may write no output before ochell
	// stops it and starts the ticket again. 0: never.
	StallTimeout time.Duration `yaml:"stall_timeout"`
	// Retry says which failed runs are started again by ochell itself.
	Retry         Retry `yaml:"retry"`
	MaxConcurrent int   `yaml:"max_concurrent"`
	// MaxAttempts is how many runs one ticket may have. A ticket that
	// reaches it is not started again until someone resets it. 0: no limit.
	MaxAttempts int    `yaml:"max_attempts"`
	QueueSize   int    `yaml:"queue_size"`
	LogDir      string `yaml:"log_dir"`
	// RunDir holds one directory per run, where the agent leaves its
	// result file for ochell. The agent must be able to write there and
	// ochell to read; it must not be inside a working directory.
	RunDir string `yaml:"run_dir"`
	// TokenExpires is the day on which the agent's own credential stops
	// working, as YYYY-MM-DD: for Claude Code, a token from "claude
	// setup-token" lasts one year. ochell cannot read the token; this is
	// where the operator notes its end. Empty: not known.
	TokenExpires string `yaml:"token_expires"`
	// TokenWarnDays is how many days before TokenExpires ochell starts to
	// warn in its log.
	TokenWarnDays int `yaml:"token_warn_days"`
	// SecretsDir is a directory of ochell's own in which the systemd
	// launcher puts, for the time of a run, the file with the run's
	// credentials (the grants of its tier). Nobody but ochell and root may
	// read it; the agent must not.
	SecretsDir string `yaml:"secrets_dir"`
}

// TokenExpiry returns the day on which the agent's credential stops
// working, as the configuration notes it: the end of that day, UTC. The
// zero time means that it is not noted.
func (a Agent) TokenExpiry() (time.Time, error) {
	if a.TokenExpires == "" {
		return time.Time{}, nil
	}
	day, err := time.Parse("2006-01-02", a.TokenExpires)
	if err != nil {
		return time.Time{}, fmt.Errorf("agent.token_expires must be a date such as 2027-11-13, not %q", a.TokenExpires)
	}
	return day.Add(24 * time.Hour), nil
}

// Retry configures the retry of runs that failed for a reason outside the
// ticket, such as a rate limit. Every retry counts as an attempt of the
// ticket (max_attempts).
type Retry struct {
	// Patterns are regular expressions. A failed run whose final message
	// (for the plain adapter: the end of its output) matches one of them
	// failed for a temporary reason and is started again. Empty: no run is
	// retried.
	Patterns []string `yaml:"patterns"`
	// Backoff is the wait before the second attempt of a ticket; it
	// doubles with each further attempt, up to MaxBackoff.
	Backoff    time.Duration `yaml:"backoff"`
	MaxBackoff time.Duration `yaml:"max_backoff"`
}

// DefaultRetryPatterns match what an agent CLI prints when the model's API
// refuses or fails a request. They are not case sensitive.
var DefaultRetryPatterns = []string{
	`(?i)rate[ _-]?limit`,
	`(?i)too many requests`,
	`(?i)overloaded`,
	`(?i)api error:? *\(?(429|5\d\d)`,
	`(?i)service unavailable|bad gateway|gateway time-?out`,
	`(?i)connection (reset|refused|timed out)`,
}

// Systemd configures the systemd launcher.
type Systemd struct {
	// LaunchCommand and StopCommand are the two root-owned scripts, with the
	// sudo prefix ochell calls them through.
	LaunchCommand []string `yaml:"launch_command"`
	StopCommand   []string `yaml:"stop_command"`
}

type JiraWebhook struct {
	Enabled      bool   `yaml:"enabled"`
	Path         string `yaml:"path"`
	Secret       string `yaml:"secret"`
	BotAccountID string `yaml:"bot_account_id"`
	// AllowedAssigners, when not empty, are the Jira accountIds of the
	// people who may assign work: the user who made the change.
	AllowedAssigners []string `yaml:"allowed_assigners"`
	// AllowedFollowUps, when not empty, says who may send follow-ups and
	// stops in comments: Jira accountIds, and the words "assigner" (who
	// assigned the ticket to the bot) and "reporter" (the ticket's
	// reporter). Empty: the same people as AllowedAssigners.
	AllowedFollowUps []string `yaml:"allowed_follow_ups"`
	// MaxSkew is how far the payload's timestamp may be from now. Jira
	// retries a failed delivery up to five times, 5 to 15 minutes apart, and
	// a retry may carry the timestamp of the event, so this must cover those
	// 75 minutes.
	MaxSkew time.Duration `yaml:"max_skew"`
}

type JiraAutomation struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	// Header carrying the token. For "Authorization" the value may be
	// prefixed with "Bearer ".
	Header       string `yaml:"header"`
	Token        string `yaml:"token"`
	BotAccountID string `yaml:"bot_account_id"`
	// AllowedAssigners, when not empty, are the Jira accountIds of the
	// people who may assign work. The rule must then send who triggered it
	// as initiatorAccountId.
	AllowedAssigners []string `yaml:"allowed_assigners"`
}

// JiraAPI is ochell's own access to the Jira REST API, as the bot account.
// The poller and the comments that ochell writes on a ticket need it; the
// webhook sources work without it. It is used when BaseURL is set.
type JiraAPI struct {
	// BaseURL is the Jira site, e.g. https://example.atlassian.net.
	BaseURL string `yaml:"base_url"`
	// Email and Token are the bot account's email address and API token.
	Email string `yaml:"email"`
	Token string `yaml:"token"`
	// JQL selects the open tickets of the bot. Empty: the open tickets
	// assigned to the account that owns the token.
	JQL string `yaml:"jql"`
	// ReviewStatus, when set, is the status a ticket is moved to when the
	// agent reports its work as done, e.g. "In Review".
	ReviewStatus string `yaml:"review_status"`
}

// Enabled reports whether the Jira API is configured.
func (j JiraAPI) Enabled() bool { return j.BaseURL != "" }

type Linear struct {
	Enabled bool          `yaml:"enabled"`
	Path    string        `yaml:"path"`
	Secret  string        `yaml:"secret"`
	MaxSkew time.Duration `yaml:"max_skew"`
	// OAuth app (actor=app) used to post agent activities back to Linear.
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
	CallbackPath string `yaml:"callback_path"`
	TokenFile    string `yaml:"token_file"`
	// AllowedAssigners, when not empty, are the Linear user ids or email
	// addresses of the people who may delegate work.
	AllowedAssigners []string `yaml:"allowed_assigners"`
	// AllowedFollowUps, when not empty, says who may send follow-ups and
	// stops in an agent session: Linear user ids or email addresses, and
	// the word "assigner" (who delegated the issue). Empty: the same
	// people as AllowedAssigners.
	AllowedFollowUps []string `yaml:"allowed_follow_ups"`
	// BotUserIDs are Linear user ids that the agent itself writes as, when
	// its ticket tool uses another account than the app. What these users
	// and the app's own user do on an issue is never taken as a person's
	// word: it starts, continues, approves and closes nothing.
	BotUserIDs []string `yaml:"bot_user_ids"`
	// ToolActivityInterval is the least time between two "action"
	// activities that show the agent's tool use in a session while it
	// runs. 0: none are posted.
	ToolActivityInterval time.Duration `yaml:"tool_activity_interval"`
	// Optional: only accept an OAuth install for this workspace.
	OrganizationID string `yaml:"organization_id"`
	// Optional: link shown on the agent session, templated with the task.
	ExternalURL string `yaml:"external_url"`
	// APIURL and TokenURL override the Linear endpoints. Only tests set them.
	APIURL   string `yaml:"api_url"`
	TokenURL string `yaml:"token_url"`
}

type Sources struct {
	JiraWebhook    JiraWebhook    `yaml:"jira_webhook"`
	JiraAutomation JiraAutomation `yaml:"jira_automation"`
	JiraAPI        JiraAPI        `yaml:"jira_api"`
	Linear         Linear         `yaml:"linear"`
}

type IPAllowlist struct {
	Enabled       bool          `yaml:"enabled"`
	AtlassianFeed bool          `yaml:"atlassian_feed"`
	LinearFeed    bool          `yaml:"linear_feed"`
	ExtraCIDRs    []string      `yaml:"extra_cidrs"`
	Refresh       time.Duration `yaml:"refresh"`
	// TrustProxyHeader uses the right-most X-Forwarded-For entry as the
	// client IP. Only enable when a trusted proxy (e.g. ngrok) is in front.
	TrustProxyHeader bool `yaml:"trust_proxy_header"`
}

type NgrokSync struct {
	Enabled           bool          `yaml:"enabled"`
	APIKey            string        `yaml:"api_key"`
	APIURL            string        `yaml:"api_url"`
	AtlassianPolicyID string        `yaml:"atlassian_policy_id"`
	LinearPolicyID    string        `yaml:"linear_policy_id"`
	Interval          time.Duration `yaml:"interval"`
}

// Store configures the file that holds ochell's durable state.
type Store struct {
	// Path is the SQLite file with the tickets, the task queue and the
	// handled webhook deliveries. It is created when missing.
	Path string `yaml:"path"`
}

// Repo maps tickets to the repository they are worked on in.
type Repo struct {
	// Source is "jira" or "linear"; empty matches both.
	Source string `yaml:"source"`
	// Project is the Jira project key or the Linear team key, which is the
	// part of the ticket key before the number (DEV in DEV-42). "*"
	// matches every project.
	Project string `yaml:"project"`
	// Label, when set, narrows the entry to tickets that carry this label
	// (in Jira also: this component).
	Label string `yaml:"label"`
	// Repo is the repository, as git clone takes it.
	Repo string `yaml:"repo"`
}

// Workspace configures the working directory of a ticket: where it may be,
// how it is prepared, and when it is removed. The hooks are ochell's own;
// they are not the hooks inside the agent's runtime.
type Workspace struct {
	// Root is the directory that every working directory must be inside.
	// Empty: not checked, and nothing is ever removed.
	Root string `yaml:"root"`
	// Branch is the branch a ticket is worked on, a template with .Key and
	// .Source. Hooks and the agent get it as ORCH_TASK_BRANCH.
	Branch string `yaml:"branch"`
	// Hooks are commands that ochell runs in the working directory, the
	// same way and as the same OS user as the agent.
	Hooks Hooks `yaml:"hooks"`
	// HookTimeout is the time limit of one hook.
	HookTimeout time.Duration `yaml:"hook_timeout"`
	// Cleanup removes the working directory of a ticket when the tracker
	// reports the ticket as closed.
	Cleanup bool `yaml:"cleanup"`
}

// Hooks are the workspace hooks. Each is a command with its arguments,
// executed without a shell; an empty list means no hook. The arguments are
// templates with .ID, .Source, .Key, .Repo and .Branch.
type Hooks struct {
	// AfterCreate runs once, before the first run in a new working
	// directory: clone the repository, create the branch.
	AfterCreate []string `yaml:"after_create"`
	// BeforeRun runs before every run: fetch, rebase.
	BeforeRun []string `yaml:"before_run"`
	// AfterRun runs after every run in which the agent was started.
	AfterRun []string `yaml:"after_run"`
	// BeforeRemove runs before the working directory is removed.
	BeforeRemove []string `yaml:"before_remove"`
}

// All returns the hooks by name, in the order they run.
func (h Hooks) All() []struct {
	Name    string
	Command []string
} {
	return []struct {
		Name    string
		Command []string
	}{
		{"after_create", h.AfterCreate}, {"before_run", h.BeforeRun},
		{"after_run", h.AfterRun}, {"before_remove", h.BeforeRemove},
	}
}

// Admin configures the local admin channel.
type Admin struct {
	// Socket is the unix socket on which a running ochell takes commands
	// (ochell pause, resume, status, reset, stop). Only ochell's own OS user can
	// open it. Empty: no admin channel.
	Socket string `yaml:"socket"`
}

// Policy points at the policy file: the risk tiers, and the rules that say
// which tier a ticket runs under (package policy).
type Policy struct {
	// File is the policy file. It must not be writable by anyone but its
	// owner, who is root or the user ochell runs as. Empty: the built-in
	// policy, with one tier for every ticket.
	File string `yaml:"file"`
}

// API configures the status API: read-only pages about what ochell is
// doing, for people. They show ticket titles and what agents said, and the
// agent runs on the same host and can reach any local port, so every
// request needs the token.
type API struct {
	Enabled bool `yaml:"enabled"`
	// Token is what a request must send as "Authorization: Bearer <token>".
	Token string `yaml:"token"`
	// PublicURL is the address under which people reach ochell's status
	// API, e.g. https://ochell.example.com. With it, the Linear session
	// of a ticket links to the ticket's entry.
	PublicURL string `yaml:"public_url"`
}

// GitHub is ochell's own, read-only access to GitHub: it asks what became
// of the pull requests that its tickets opened. It is used when Token is
// set. The token needs read access to pull requests and nothing else; it
// is not the agent's.
type GitHub struct {
	Token string `yaml:"token"`
	// APIURL is the address of the API. Empty: github.com. For GitHub
	// Enterprise Server, https://<host>/api/v3.
	APIURL string `yaml:"api_url"`
	// PollInterval is how often ochell asks about the open pull requests.
	PollInterval time.Duration `yaml:"poll_interval"`
	// BotLogin is the GitHub login of the digital employee. A pull request
	// that this account merged itself is not taken as accepted work.
	BotLogin string `yaml:"bot_login"`
	// ChecksGrace is how long ochell waits for a check to appear on a
	// pull request before it takes the pull request to have none.
	ChecksGrace time.Duration `yaml:"checks_grace"`
	// AllowedReviewers are the GitHub logins whose comments on a pull
	// request are passed on to the agent. Empty: the people whom GitHub
	// calls owner, member or collaborator of the repository.
	AllowedReviewers []string `yaml:"allowed_reviewers"`
}

// Enabled reports whether the GitHub access is configured.
func (g GitHub) Enabled() bool { return g.Token != "" }

// Workflow lets a repository say how its tickets are worked, in a file
// WORKFLOW.md on its default branch (package workflow): the prompt, hooks,
// the status of the hand-over, and limits that are stricter than the
// tier's. The file can only narrow the policy; what it may add at all is
// set here.
type Workflow struct {
	// Enabled makes ochell read the file of each ticket's repository, at
	// the start of every run. It needs the GitHub access (github.token,
	// with read access to the contents of the repositories).
	Enabled bool `yaml:"enabled"`
	// AllowHooks lets a repository add hooks of its own, which run after
	// the host's. They are commands that run as the agent's OS user for
	// every ticket of the repository, so the host has to say yes.
	AllowHooks bool `yaml:"allow_hooks"`
	// ReviewStatuses are the Jira statuses that a repository may choose
	// from for the hand-over, in the place of
	// sources.jira_api.review_status. Empty: a repository cannot choose.
	ReviewStatuses []string `yaml:"review_statuses"`
}

// Retention says how long ochell keeps what its runs leave behind. Run
// logs hold prompts and ticket text, so they should not stay for ever.
type Retention struct {
	// Logs is how long a run's log file and its run directory (with the
	// result file) are kept after they were last written. 0: for ever.
	Logs time.Duration `yaml:"logs"`
	// Interval is how often ochell looks for what is too old, and for
	// working directories of closed tickets that are still there.
	Interval time.Duration `yaml:"interval"`
}

// Backup configures the scheduled backup of the store. The store holds what
// cannot be rebuilt from the trackers: the agents' session ids, queued
// follow-ups and the record of every run.
type Backup struct {
	// Dir is where the backups go: a directory that the agent cannot read,
	// best on another disk than the store. Empty: no scheduled backup.
	Dir string `yaml:"dir"`
	// Interval is the time between two backups.
	Interval time.Duration `yaml:"interval"`
	// Keep is how many backups stay; older ones are removed. 0: all.
	Keep int `yaml:"keep"`
}

// Metrics configures the metrics endpoint: counters and gauges about the
// runs, in the Prometheus text format, at GET /metrics on the listeners of
// the webhooks.
type Metrics struct {
	Enabled bool `yaml:"enabled"`
	// Token is what a scrape must send as "Authorization: Bearer <token>".
	// The agent runs on the same host and can reach any local port.
	Token string `yaml:"token"`
}

// TicketTools configures ochell's own MCP server: tools with which an
// agent reads and comments on the ticket of its run, through ochell and
// with ochell's access to the tracker, so that the agent needs no tracker
// token. Which runs get them is the policy's to say (grants.ticket_tools
// of a tier).
type TicketTools struct {
	Enabled bool `yaml:"enabled"`
	// URL is the address under which an agent on this host reaches the
	// server. Empty: the HTTP listener on the loopback address, with the
	// server's path.
	URL string `yaml:"url"`
}

// ticketToolsPath is where the server is mounted (mcp.Path).
const ticketToolsPath = "/mcp"

// TicketToolsURL returns the address of the ticket tools for an agent: URL, or
// the HTTP listener.
func (c *Config) TicketToolsURL() string {
	if c.TicketTools.URL != "" {
		return c.TicketTools.URL
	}
	host := c.HTTP.Address
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		// The listener takes every address; the agent is on this host.
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(c.HTTP.Port)) + ticketToolsPath
}

// Poller configures the safety net behind the webhooks: ochell asks each
// tracker for the bot's open tickets, at start and then at this interval.
type Poller struct {
	// Interval is the time between two polls. 0: no polling.
	Interval time.Duration `yaml:"interval"`
}

type Config struct {
	LogLevel string   `yaml:"log_level"`
	HTTP     Listener `yaml:"http"`
	HTTPS    Listener `yaml:"https"`
	Admin    Admin    `yaml:"admin"`
	Store    Store    `yaml:"store"`
	Policy   Policy   `yaml:"policy"`
	API      API      `yaml:"api"`
	GitHub   GitHub   `yaml:"github"`
	// Repos says which repository a ticket belongs to. The first entry
	// that matches wins. When the list is not empty, a ticket that no
	// entry matches is not started and waits for a human. When it is
	// empty, tickets run without a repository.
	Repos       []Repo      `yaml:"repos"`
	Workspace   Workspace   `yaml:"workspace"`
	Workflow    Workflow    `yaml:"workflow"`
	Poller      Poller      `yaml:"poller"`
	Retention   Retention   `yaml:"retention"`
	Backup      Backup      `yaml:"backup"`
	Metrics     Metrics     `yaml:"metrics"`
	TicketTools TicketTools `yaml:"ticket_tools"`
	Agent       Agent       `yaml:"agent"`
	Sources     Sources     `yaml:"sources"`
	IPAllowlist IPAllowlist `yaml:"ip_allowlist"`
	NgrokSync   NgrokSync   `yaml:"ngrok_sync"`
}

// ProjectOf returns the project of a ticket key: the part before the last
// "-" (DEV in DEV-42), or the whole key when there is none.
func ProjectOf(key string) string {
	if i := strings.LastIndexByte(key, '-'); i > 0 {
		return key[:i]
	}
	return key
}

// RepoFor returns the repository of a ticket: that of the first entry of
// repos that matches its source, its project and, where the entry names
// one, one of its labels. ok is false when no entry matches.
func (c *Config) RepoFor(source, key string, labels []string) (repo string, ok bool) {
	project := ProjectOf(key)
	for _, r := range c.Repos {
		if r.Source != "" && r.Source != source {
			continue
		}
		if r.Project != "*" && !strings.EqualFold(r.Project, project) {
			continue
		}
		if r.Label != "" && !slices.ContainsFunc(labels, func(l string) bool { return strings.EqualFold(l, r.Label) }) {
			continue
		}
		return r.Repo, true
	}
	return "", false
}

const DefaultPromptTemplate = `You are the digital employee assigned {{.Source}} ticket {{.Key}} ({{.URL}}).
{{if .TicketTools}}Read the full ticket with the tool get_ticket of the MCP server "ochell"{{else}}Use twg to retrieve the full ticket details{{end}}, complete the task, and open a pull request.
{{- if .Repo}}
The repository for this ticket is {{.Repo}}.
{{- end}}
{{- if .Context}}

Context provided by {{.Source}}:
{{.Context}}
{{- end}}
{{- if .RunContext}}

{{.RunContext}}
{{- end}}

{{.ResultInstructions}}
`

// DefaultEnvPass is what an agent CLI needs to find its binaries, home
// directory, locale, proxy and CA settings. It holds no ochell secret.
var DefaultEnvPass = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

func Default() *Config {
	return &Config{
		LogLevel:  "info",
		HTTP:      Listener{Enabled: true, Address: "0.0.0.0", Port: 8080},
		HTTPS:     Listener{Enabled: false, Address: "0.0.0.0", Port: 8443},
		Admin:     Admin{Socket: "ochell.sock"},
		Store:     Store{Path: "ochell.db"},
		Workspace: Workspace{Branch: "bot/{{.Key}}", HookTimeout: 10 * time.Minute},
		Poller:    Poller{Interval: 5 * time.Minute},
		Retention: Retention{Logs: 30 * 24 * time.Hour, Interval: time.Hour},
		Backup:    Backup{Interval: 24 * time.Hour, Keep: 7},
		GitHub:    GitHub{PollInterval: 2 * time.Minute, ChecksGrace: 2 * time.Minute},
		Agent: Agent{
			Command:        "claude",
			Args:           []string{"-p"},
			PromptVia:      "stdin",
			PromptTemplate: DefaultPromptTemplate,
			Workdir:        ".",
			Adapter:        "plain",
			Launcher:       "direct",
			Systemd: Systemd{
				LaunchCommand: []string{"sudo", "-n", "/usr/local/libexec/ochell/ochell-launch"},
				StopCommand:   []string{"sudo", "-n", "/usr/local/libexec/ochell/ochell-stop"},
			},
			StopGrace:    10 * time.Second,
			DrainTimeout: 30 * time.Second,
			EnvPass:      append([]string(nil), DefaultEnvPass...),
			Timeout:      2 * time.Hour,
			Retry: Retry{
				Patterns:   append([]string(nil), DefaultRetryPatterns...),
				Backoff:    time.Minute,
				MaxBackoff: 30 * time.Minute,
			},
			MaxConcurrent: 1,
			MaxAttempts:   5,
			QueueSize:     100,
			LogDir:        "logs",
			RunDir:        "runs",
			TokenWarnDays: 30,
			SecretsDir:    "secrets",
		},
		Sources: Sources{
			JiraWebhook:    JiraWebhook{Path: "/webhooks/jira", MaxSkew: 2 * time.Hour},
			JiraAutomation: JiraAutomation{Path: "/webhooks/jira-automation", Header: "Authorization"},
			Linear: Linear{
				Path:                 "/webhooks/linear",
				MaxSkew:              60 * time.Second,
				ToolActivityInterval: 30 * time.Second,
				CallbackPath:         "/oauth/linear/callback",
				TokenFile:            "linear-token.json",
			},
		},
		IPAllowlist: IPAllowlist{AtlassianFeed: true, LinearFeed: true, Refresh: time.Hour},
		NgrokSync:   NgrokSync{APIURL: "https://api.ngrok.com", Interval: 6 * time.Hour},
	}
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${VAR} references only, so "$" in other values is kept.
func expandEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string {
		return os.Getenv(envRef.FindStringSubmatch(m)[1])
	})
}

// LoadFile merges a YAML file into cfg.
func LoadFile(cfg *Config, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(expandEnv(string(raw))))
	dec.KnownFields(true)
	// An empty file decodes as io.EOF and leaves the defaults in place.
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// stringList is a repeatable flag; the first use replaces the YAML value.
type stringList struct {
	dst *[]string
	set bool
}

func (s *stringList) String() string {
	if s.dst == nil {
		return ""
	}
	return strings.Join(*s.dst, " ")
}

func (s *stringList) Set(v string) error {
	if !s.set {
		*s.dst = nil
		s.set = true
	}
	*s.dst = append(*s.dst, v)
	return nil
}

// findConfigArg returns the value of -config/--config without parsing the
// remaining flags, so the YAML file can be loaded before flags are bound.
func findConfigArg(args []string) string {
	for i, a := range args {
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			continue
		}
		if hasVal {
			return val
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// Load builds the configuration for the given command line arguments.
// extra, when non-nil, lets a subcommand register its own flags.
func Load(name string, args []string, extra func(fs *flag.FlagSet)) (*Config, error) {
	cfg := Default()
	cfgFile := findConfigArg(args)
	if cfgFile != "" {
		if err := LoadFile(cfg, cfgFile); err != nil {
			return nil, err
		}
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.String("config", cfgFile, "YAML configuration file")
	bindFlags(fs, cfg)
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return cfg, nil
}

func bindFlags(fs *flag.FlagSet, c *Config) {
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "log level: debug, info, warn, error")

	fs.BoolVar(&c.HTTP.Enabled, "http", c.HTTP.Enabled, "enable the HTTP listener")
	fs.StringVar(&c.HTTP.Address, "http-addr", c.HTTP.Address, "HTTP listen address")
	fs.IntVar(&c.HTTP.Port, "http-port", c.HTTP.Port, "HTTP listen port")
	fs.BoolVar(&c.HTTPS.Enabled, "https", c.HTTPS.Enabled, "enable the HTTPS listener")
	fs.StringVar(&c.HTTPS.Address, "https-addr", c.HTTPS.Address, "HTTPS listen address")
	fs.IntVar(&c.HTTPS.Port, "https-port", c.HTTPS.Port, "HTTPS listen port")
	fs.StringVar(&c.HTTPS.CertFile, "tls-cert", c.HTTPS.CertFile, "TLS certificate file (PEM)")
	fs.StringVar(&c.HTTPS.KeyFile, "tls-key", c.HTTPS.KeyFile, "TLS private key file (PEM)")

	fs.StringVar(&c.Admin.Socket, "admin-socket", c.Admin.Socket, "unix socket of the admin channel (ochell pause, resume, status, reset, stop)")
	fs.StringVar(&c.Store.Path, "store-path", c.Store.Path, "file that holds the tickets, the task queue and the handled deliveries")

	fs.StringVar(&c.Policy.File, "policy-file", c.Policy.File, "policy file with the risk tiers (empty: one built-in tier for every ticket)")

	fs.DurationVar(&c.Poller.Interval, "poll-interval", c.Poller.Interval, "how often ochell asks the trackers for the bot's open tickets (0: never)")

	fs.StringVar(&c.Agent.Command, "agent-cmd", c.Agent.Command, "agent CLI command")
	fs.Var(&stringList{dst: &c.Agent.Args}, "agent-arg", "agent CLI argument, repeatable, Go template (replaces config args)")
	fs.StringVar(&c.Agent.PromptVia, "agent-prompt-via", c.Agent.PromptVia, "how the prompt is passed: stdin or arg")
	fs.StringVar(&c.Agent.Adapter, "agent-adapter", c.Agent.Adapter, "kind of agent CLI: plain or claude")
	fs.StringVar(&c.Agent.Launcher, "agent-launcher", c.Agent.Launcher, "how the agent is run: direct or systemd")
	fs.Var(&stringList{dst: &c.Agent.EnvPass}, "agent-env-pass", "environment variable the agent inherits from ochell, repeatable (replaces config env_pass)")
	fs.StringVar(&c.Agent.Workdir, "agent-workdir", c.Agent.Workdir, "agent working directory, Go template")
	fs.DurationVar(&c.Agent.Timeout, "agent-timeout", c.Agent.Timeout, "maximum agent run time")
	fs.DurationVar(&c.Agent.StallTimeout, "agent-stall-timeout", c.Agent.StallTimeout, "stop an agent that wrote no output for this long, and start the ticket again (0: never)")
	fs.DurationVar(&c.Agent.StopGrace, "agent-stop-grace", c.Agent.StopGrace, "time between SIGTERM and SIGKILL when an agent is stopped")
	fs.DurationVar(&c.Agent.DrainTimeout, "agent-drain-timeout", c.Agent.DrainTimeout, "how long a shutdown waits for running agents before it stops them")
	fs.IntVar(&c.Agent.MaxConcurrent, "agent-max-concurrent", c.Agent.MaxConcurrent, "maximum concurrent agent runs")
	fs.IntVar(&c.Agent.MaxAttempts, "agent-max-attempts", c.Agent.MaxAttempts, "maximum number of runs of one ticket (0: no limit)")
	fs.StringVar(&c.Agent.LogDir, "agent-log-dir", c.Agent.LogDir, "directory for per-task agent logs")
	fs.StringVar(&c.Agent.RunDir, "agent-run-dir", c.Agent.RunDir, "directory where each run leaves its result file for ochell")

	fs.BoolVar(&c.Sources.JiraWebhook.Enabled, "jira-webhook", c.Sources.JiraWebhook.Enabled, "enable the Jira native webhook source")
	fs.StringVar(&c.Sources.JiraWebhook.Path, "jira-webhook-path", c.Sources.JiraWebhook.Path, "Jira native webhook path")
	fs.StringVar(&c.Sources.JiraWebhook.Secret, "jira-webhook-secret", c.Sources.JiraWebhook.Secret, "Jira native webhook HMAC secret")
	fs.StringVar(&c.Sources.JiraWebhook.BotAccountID, "jira-bot-account-id", c.Sources.JiraWebhook.BotAccountID, "Jira accountId of the digital employee")

	fs.BoolVar(&c.Sources.JiraAutomation.Enabled, "jira-automation", c.Sources.JiraAutomation.Enabled, "enable the Jira Automation source")
	fs.StringVar(&c.Sources.JiraAutomation.Path, "jira-automation-path", c.Sources.JiraAutomation.Path, "Jira Automation webhook path")
	fs.StringVar(&c.Sources.JiraAutomation.Header, "jira-automation-header", c.Sources.JiraAutomation.Header, "header carrying the Jira Automation token")
	fs.StringVar(&c.Sources.JiraAutomation.Token, "jira-automation-token", c.Sources.JiraAutomation.Token, "Jira Automation shared token")

	fs.BoolVar(&c.Sources.Linear.Enabled, "linear", c.Sources.Linear.Enabled, "enable the Linear agent source")
	fs.StringVar(&c.Sources.Linear.Path, "linear-path", c.Sources.Linear.Path, "Linear webhook path")
	fs.StringVar(&c.Sources.Linear.Secret, "linear-secret", c.Sources.Linear.Secret, "Linear webhook signing secret")
	fs.StringVar(&c.Sources.Linear.ClientID, "linear-client-id", c.Sources.Linear.ClientID, "Linear OAuth client id")
	fs.StringVar(&c.Sources.Linear.ClientSecret, "linear-client-secret", c.Sources.Linear.ClientSecret, "Linear OAuth client secret")
	fs.StringVar(&c.Sources.Linear.RedirectURL, "linear-redirect-url", c.Sources.Linear.RedirectURL, "public URL of the Linear OAuth callback")
	fs.StringVar(&c.Sources.Linear.TokenFile, "linear-token-file", c.Sources.Linear.TokenFile, "file storing the Linear OAuth token")

	fs.BoolVar(&c.IPAllowlist.Enabled, "ip-allowlist", c.IPAllowlist.Enabled, "enforce source IP allowlists in the orchestrator")
	fs.BoolVar(&c.IPAllowlist.TrustProxyHeader, "trust-proxy-header", c.IPAllowlist.TrustProxyHeader, "use X-Forwarded-For for the client IP")

	fs.BoolVar(&c.NgrokSync.Enabled, "ngrok-sync", c.NgrokSync.Enabled, "periodically sync IP feeds into ngrok IP policies while serving")
	fs.StringVar(&c.NgrokSync.APIKey, "ngrok-api-key", c.NgrokSync.APIKey, "ngrok API key")
	fs.StringVar(&c.NgrokSync.AtlassianPolicyID, "ngrok-atlassian-policy", c.NgrokSync.AtlassianPolicyID, "ngrok IP policy id for Atlassian ranges")
	fs.StringVar(&c.NgrokSync.LinearPolicyID, "ngrok-linear-policy", c.NgrokSync.LinearPolicyID, "ngrok IP policy id for Linear ranges")
}

// Validate checks the settings of the Jira API, when it is configured.
func (j JiraAPI) Validate() error {
	if !j.Enabled() {
		if j.Email != "" || j.Token != "" {
			return errors.New("sources.jira_api: email and token are set but base_url is not")
		}
		return nil
	}
	var errs []error
	u, err := url.Parse(j.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		errs = append(errs, errors.New("sources.jira_api.base_url must be the address of the Jira site, such as https://example.atlassian.net"))
	}
	if j.Email == "" || j.Token == "" {
		errs = append(errs, errors.New("sources.jira_api requires email and token: the bot account's email address and API token"))
	}
	return errors.Join(errs...)
}

// Validate checks the configuration needed to serve webhooks.
func (c *Config) Validate() error {
	var errs []error
	if !c.HTTP.Enabled && !c.HTTPS.Enabled {
		errs = append(errs, errors.New("at least one of http or https must be enabled"))
	}
	if c.HTTP.Enabled && c.HTTPS.Enabled && c.HTTP.Addr() == c.HTTPS.Addr() {
		errs = append(errs, errors.New("http and https cannot use the same address and port"))
	}
	if c.HTTPS.Enabled && (c.HTTPS.CertFile == "" || c.HTTPS.KeyFile == "") {
		errs = append(errs, errors.New("https requires cert_file and key_file"))
	}
	if c.Store.Path == "" {
		errs = append(errs, errors.New("store.path is required"))
	}
	if c.API.Enabled && len(c.API.Token) < 16 {
		errs = append(errs, errors.New("api.token is required when the status API is enabled, with at least 16 characters"))
	}
	if c.API.PublicURL != "" {
		if u, err := url.Parse(c.API.PublicURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" {
			errs = append(errs, errors.New("api.public_url must be an address such as https://ochell.example.com"))
		}
		if !c.API.Enabled {
			errs = append(errs, errors.New("api.public_url is set but the status API is not enabled"))
		}
	}
	for i, r := range c.Repos {
		if r.Source != "" && r.Source != "jira" && r.Source != "linear" {
			errs = append(errs, fmt.Errorf("repos[%d].source must be jira, linear or empty", i))
		}
		if r.Project == "" {
			errs = append(errs, fmt.Errorf(`repos[%d].project is required; "*" matches every project`, i))
		}
		// The value reaches the agent's environment and prompt.
		if r.Repo == "" || strings.ContainsAny(r.Repo, " \t\n\r") {
			errs = append(errs, fmt.Errorf("repos[%d].repo is required, without spaces", i))
		}
	}
	ws := c.Workspace
	if ws.Root != "" && !strings.HasPrefix(ws.Root, "/") {
		errs = append(errs, errors.New("workspace.root must be an absolute path"))
	}
	if ws.Branch == "" {
		errs = append(errs, errors.New("workspace.branch is required"))
	}
	if ws.HookTimeout <= 0 {
		errs = append(errs, errors.New("workspace.hook_timeout must be positive"))
	}
	if ws.Cleanup {
		// A working directory is only removed when it cannot be anything
		// but the directory of one ticket, inside a known root.
		if ws.Root == "" {
			errs = append(errs, errors.New("workspace.cleanup requires workspace.root"))
		}
		if !strings.Contains(c.Agent.Workdir, ".Key") {
			errs = append(errs, errors.New("workspace.cleanup requires agent.workdir to contain {{.Key}}, so that each ticket has a directory of its own"))
		}
	}
	for _, h := range ws.Hooks.All() {
		if len(h.Command) == 0 {
			continue
		}
		if h.Command[0] == "" {
			errs = append(errs, fmt.Errorf("workspace.hooks.%s: the command is empty", h.Name))
		}
		// PATH in the unit is the system default.
		if c.Agent.Launcher == "systemd" && !strings.HasPrefix(h.Command[0], "/") {
			errs = append(errs, fmt.Errorf("workspace.hooks.%s: agent.launcher systemd requires the command to be an absolute path", h.Name))
		}
	}
	if g := c.GitHub; g.Enabled() {
		if g.PollInterval <= 0 {
			errs = append(errs, errors.New("github.poll_interval must be positive"))
		}
		if g.ChecksGrace < 0 {
			errs = append(errs, errors.New("github.checks_grace must not be negative"))
		}
		if g.APIURL != "" {
			if u, err := url.Parse(g.APIURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				errs = append(errs, errors.New("github.api_url must be the address of the API, such as https://ghe.example.com/api/v3"))
			}
		}
	} else if g.APIURL != "" || g.BotLogin != "" {
		errs = append(errs, errors.New("github: api_url or bot_login is set but token is not"))
	}
	if wf := c.Workflow; wf.Enabled {
		// The file is read from the default branch through GitHub's API,
		// never from a working directory.
		if !c.GitHub.Enabled() {
			errs = append(errs, errors.New("workflow.enabled requires github.token: a repository's WORKFLOW.md is read from its default branch through ochell's access to GitHub"))
		}
		for _, s := range wf.ReviewStatuses {
			if strings.TrimSpace(s) == "" {
				errs = append(errs, errors.New("workflow.review_statuses: an empty entry"))
			}
		}
	} else if wf.AllowHooks || len(wf.ReviewStatuses) > 0 {
		errs = append(errs, errors.New("workflow: allow_hooks or review_statuses is set but enabled is not"))
	}
	if c.Retention.Logs < 0 {
		errs = append(errs, errors.New("retention.logs must not be negative; 0s keeps the logs for ever"))
	}
	if c.Retention.Interval <= 0 {
		errs = append(errs, errors.New("retention.interval must be positive"))
	}
	if c.Backup.Dir != "" && c.Backup.Interval <= 0 {
		errs = append(errs, errors.New("backup.interval must be positive"))
	}
	if c.Backup.Keep < 0 {
		errs = append(errs, errors.New("backup.keep must not be negative; 0 keeps every backup"))
	}
	if c.Metrics.Enabled && len(c.Metrics.Token) < 16 {
		errs = append(errs, errors.New("metrics.token is required when the metrics endpoint is enabled, with at least 16 characters"))
	}
	if tt := c.TicketTools; tt.Enabled {
		if tt.URL == "" && !c.HTTP.Enabled {
			errs = append(errs, errors.New("ticket_tools.url is required when the http listener is off: the address under which an agent on this host reaches ochell, such as https://ochell.example.com/mcp"))
		}
		if tt.URL != "" {
			if u, err := url.Parse(tt.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Path != ticketToolsPath {
				errs = append(errs, errors.New("ticket_tools.url must be the address of one of ochell's listeners with the path "+ticketToolsPath+", such as http://127.0.0.1:8080/mcp"))
			}
		}
		// The tools use ochell's own access to each tracker.
		if (c.Sources.JiraWebhook.Enabled || c.Sources.JiraAutomation.Enabled) && !c.Sources.JiraAPI.Enabled() {
			errs = append(errs, errors.New("ticket_tools needs sources.jira_api for the Jira tickets: the tools read and comment with ochell's own access to Jira"))
		}
		if c.Sources.Linear.Enabled && c.Sources.Linear.ClientID == "" {
			errs = append(errs, errors.New("ticket_tools needs the Linear app (sources.linear.client_id) for the Linear tickets: the tools read and comment with the app's token"))
		}
		// A comment that the agent makes through the tools is written by
		// the account of sources.jira_api. It must be known as the bot's,
		// or it would start a run like a person's comment.
		if c.Sources.JiraWebhook.Enabled && c.Sources.JiraWebhook.BotAccountID == "" {
			errs = append(errs, errors.New("ticket_tools needs sources.jira_webhook.bot_account_id: the account of sources.jira_api, whose comments are never taken as a person's"))
		}
	} else if c.TicketTools.URL != "" {
		errs = append(errs, errors.New("ticket_tools.url is set but ticket_tools.enabled is not"))
	}
	if _, err := c.Agent.TokenExpiry(); err != nil {
		errs = append(errs, err)
	}
	if c.Agent.TokenWarnDays < 0 {
		errs = append(errs, errors.New("agent.token_warn_days must not be negative"))
	}
	if c.Poller.Interval < 0 {
		errs = append(errs, errors.New("poller.interval must not be negative; 0s turns the poller off"))
	}
	if c.Agent.Command == "" {
		errs = append(errs, errors.New("agent.command is required"))
	}
	if c.Agent.PromptVia != "arg" && c.Agent.PromptVia != "stdin" {
		errs = append(errs, errors.New("agent.prompt_via must be stdin or arg"))
	}
	// Without the instructions no agent writes a result file, and every
	// run would end as "no result".
	if !strings.Contains(c.Agent.PromptTemplate, ".ResultInstructions") {
		errs = append(errs, errors.New("agent.prompt_template must include {{.ResultInstructions}}: it tells the agent how to report the result of its run"))
	}
	// Without the run context a later attempt does not know about the
	// earlier ones, or about the comment that asked for it.
	if !strings.Contains(c.Agent.PromptTemplate, ".RunContext") {
		errs = append(errs, errors.New("agent.prompt_template must include {{.RunContext}}: it tells the agent which attempt this is, what earlier attempts left, and which comment asked for the run"))
	}
	if c.Agent.RunDir == "" {
		errs = append(errs, errors.New("agent.run_dir is required"))
	}
	if c.Agent.PromptVia == "stdin" {
		for _, a := range c.Agent.Args {
			if strings.Contains(a, ".Prompt") {
				errs = append(errs, errors.New("agent.args references .Prompt but prompt_via is stdin: remove it from args, or set prompt_via: arg"))
				break
			}
		}
	}
	switch c.Agent.Adapter {
	case "plain":
	case "claude":
		if c.Agent.PromptVia != "stdin" {
			errs = append(errs, errors.New("agent.adapter claude requires prompt_via: stdin"))
		}
	default:
		errs = append(errs, errors.New("agent.adapter must be plain or claude"))
	}
	switch c.Agent.Launcher {
	case "direct":
	case "systemd":
		// systemd replaces ${VAR} in the unit's arguments from its
		// environment, which holds the agent's token, so ticket text must
		// never be an argument.
		if c.Agent.PromptVia != "stdin" {
			errs = append(errs, errors.New("agent.launcher systemd requires prompt_via: stdin"))
		}
		// PATH in the unit is the system default.
		if !strings.HasPrefix(c.Agent.Command, "/") {
			errs = append(errs, errors.New("agent.launcher systemd requires agent.command to be an absolute path"))
		}
		// The launch script refuses any other working directory, which
		// would make every run end as not started.
		if !strings.HasPrefix(c.Agent.Workdir, "/") {
			errs = append(errs, errors.New("agent.launcher systemd requires agent.workdir to be an absolute path, inside the launcher's WORKSPACE_ROOT"))
		}
		// The launch script creates the run directory as the agent user,
		// and only inside the workspace root.
		if !strings.HasPrefix(c.Agent.RunDir, "/") {
			errs = append(errs, errors.New("agent.launcher systemd requires agent.run_dir to be an absolute path, inside the launcher's WORKSPACE_ROOT"))
		}
		if len(c.Agent.Systemd.LaunchCommand) == 0 || len(c.Agent.Systemd.StopCommand) == 0 {
			errs = append(errs, errors.New("agent.systemd requires launch_command and stop_command"))
		}
	default:
		errs = append(errs, errors.New("agent.launcher must be direct or systemd"))
	}
	if c.Agent.StopGrace < 0 {
		errs = append(errs, errors.New("agent.stop_grace must not be negative"))
	}
	if c.Agent.DrainTimeout < 0 {
		errs = append(errs, errors.New("agent.drain_timeout must not be negative"))
	}
	for _, n := range c.Agent.EnvPass {
		if !envName.MatchString(n) {
			errs = append(errs, fmt.Errorf("agent.env_pass: %q is not a variable name", n))
		}
	}
	for n := range c.Agent.Env {
		if !envName.MatchString(n) {
			errs = append(errs, fmt.Errorf("agent.env: %q is not a variable name", n))
		}
	}
	if c.Agent.StallTimeout < 0 {
		errs = append(errs, errors.New("agent.stall_timeout must not be negative"))
	}
	for i, p := range c.Agent.Retry.Patterns {
		if _, err := regexp.Compile(p); err != nil || p == "" {
			errs = append(errs, fmt.Errorf("agent.retry.patterns[%d] is not a regular expression: %v", i, err))
		}
	}
	if len(c.Agent.Retry.Patterns) > 0 && (c.Agent.Retry.Backoff <= 0 || c.Agent.Retry.MaxBackoff < c.Agent.Retry.Backoff) {
		errs = append(errs, errors.New("agent.retry: backoff must be positive, and max_backoff not below it"))
	}
	if c.Agent.MaxConcurrent < 1 {
		errs = append(errs, errors.New("agent.max_concurrent must be >= 1"))
	}
	if c.Agent.MaxAttempts < 0 {
		errs = append(errs, errors.New("agent.max_attempts must not be negative"))
	}

	s := c.Sources
	if !s.JiraWebhook.Enabled && !s.JiraAutomation.Enabled && !s.Linear.Enabled {
		errs = append(errs, errors.New("no source enabled"))
	}
	if s.JiraWebhook.Enabled {
		if s.JiraWebhook.Secret == "" {
			errs = append(errs, errors.New("sources.jira_webhook.secret is required"))
		}
		if s.JiraWebhook.BotAccountID == "" {
			errs = append(errs, errors.New("sources.jira_webhook.bot_account_id is required"))
		}
		if s.JiraWebhook.MaxSkew <= 0 {
			errs = append(errs, errors.New("sources.jira_webhook.max_skew must be positive"))
		}
	}
	if s.JiraAutomation.Enabled && (s.JiraAutomation.Token == "" || s.JiraAutomation.Header == "") {
		errs = append(errs, errors.New("sources.jira_automation requires header and token"))
	}
	if err := s.JiraAPI.Validate(); err != nil {
		errs = append(errs, err)
	}
	if s.Linear.ToolActivityInterval < 0 {
		errs = append(errs, errors.New("sources.linear.tool_activity_interval must not be negative; 0s posts no tool use"))
	}
	if s.Linear.Enabled && s.Linear.Secret == "" {
		errs = append(errs, errors.New("sources.linear.secret is required"))
	}
	paths := map[string]string{}
	for name, p := range map[string]struct {
		on   bool
		path string
	}{
		"jira_webhook":    {s.JiraWebhook.Enabled, s.JiraWebhook.Path},
		"jira_automation": {s.JiraAutomation.Enabled, s.JiraAutomation.Path},
		"linear":          {s.Linear.Enabled, s.Linear.Path},
	} {
		if !p.on {
			continue
		}
		if !strings.HasPrefix(p.path, "/") {
			errs = append(errs, fmt.Errorf("sources.%s.path must start with /", name))
		}
		if other, dup := paths[p.path]; dup {
			errs = append(errs, fmt.Errorf("sources.%s and %s share path %s", name, other, p.path))
		}
		paths[p.path] = name
	}
	return errors.Join(errs...)
}
