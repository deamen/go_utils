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
	"os"
	"regexp"
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
	Env           map[string]string `yaml:"env"`
	Timeout       time.Duration     `yaml:"timeout"`
	MaxConcurrent int               `yaml:"max_concurrent"`
	QueueSize     int               `yaml:"queue_size"`
	LogDir        string            `yaml:"log_dir"`
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
}

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

type Config struct {
	LogLevel    string      `yaml:"log_level"`
	HTTP        Listener    `yaml:"http"`
	HTTPS       Listener    `yaml:"https"`
	Store       Store       `yaml:"store"`
	Agent       Agent       `yaml:"agent"`
	Sources     Sources     `yaml:"sources"`
	IPAllowlist IPAllowlist `yaml:"ip_allowlist"`
	NgrokSync   NgrokSync   `yaml:"ngrok_sync"`
}

const DefaultPromptTemplate = `You are the digital employee assigned {{.Source}} ticket {{.Key}} ({{.URL}}).
Use twg to retrieve the full ticket details, complete the task, and open a pull request.
{{- if .Context}}

Context provided by {{.Source}}:
{{.Context}}
{{- end}}
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
		LogLevel: "info",
		HTTP:     Listener{Enabled: true, Address: "0.0.0.0", Port: 8080},
		HTTPS:    Listener{Enabled: false, Address: "0.0.0.0", Port: 8443},
		Store:    Store{Path: "ochell.db"},
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
			StopGrace:     10 * time.Second,
			DrainTimeout:  30 * time.Second,
			EnvPass:       append([]string(nil), DefaultEnvPass...),
			Timeout:       2 * time.Hour,
			MaxConcurrent: 1,
			QueueSize:     100,
			LogDir:        "logs",
		},
		Sources: Sources{
			JiraWebhook:    JiraWebhook{Path: "/webhooks/jira", MaxSkew: 2 * time.Hour},
			JiraAutomation: JiraAutomation{Path: "/webhooks/jira-automation", Header: "Authorization"},
			Linear: Linear{
				Path:         "/webhooks/linear",
				MaxSkew:      60 * time.Second,
				CallbackPath: "/oauth/linear/callback",
				TokenFile:    "linear-token.json",
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

	fs.StringVar(&c.Store.Path, "store-path", c.Store.Path, "file that holds the tickets, the task queue and the handled deliveries")

	fs.StringVar(&c.Agent.Command, "agent-cmd", c.Agent.Command, "agent CLI command")
	fs.Var(&stringList{dst: &c.Agent.Args}, "agent-arg", "agent CLI argument, repeatable, Go template (replaces config args)")
	fs.StringVar(&c.Agent.PromptVia, "agent-prompt-via", c.Agent.PromptVia, "how the prompt is passed: stdin or arg")
	fs.StringVar(&c.Agent.Adapter, "agent-adapter", c.Agent.Adapter, "kind of agent CLI: plain or claude")
	fs.StringVar(&c.Agent.Launcher, "agent-launcher", c.Agent.Launcher, "how the agent is run: direct or systemd")
	fs.Var(&stringList{dst: &c.Agent.EnvPass}, "agent-env-pass", "environment variable the agent inherits from ochell, repeatable (replaces config env_pass)")
	fs.StringVar(&c.Agent.Workdir, "agent-workdir", c.Agent.Workdir, "agent working directory, Go template")
	fs.DurationVar(&c.Agent.Timeout, "agent-timeout", c.Agent.Timeout, "maximum agent run time")
	fs.DurationVar(&c.Agent.StopGrace, "agent-stop-grace", c.Agent.StopGrace, "time between SIGTERM and SIGKILL when an agent is stopped")
	fs.DurationVar(&c.Agent.DrainTimeout, "agent-drain-timeout", c.Agent.DrainTimeout, "how long a shutdown waits for running agents before it stops them")
	fs.IntVar(&c.Agent.MaxConcurrent, "agent-max-concurrent", c.Agent.MaxConcurrent, "maximum concurrent agent runs")
	fs.StringVar(&c.Agent.LogDir, "agent-log-dir", c.Agent.LogDir, "directory for per-task agent logs")

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
	if c.Agent.Command == "" {
		errs = append(errs, errors.New("agent.command is required"))
	}
	if c.Agent.PromptVia != "arg" && c.Agent.PromptVia != "stdin" {
		errs = append(errs, errors.New("agent.prompt_via must be stdin or arg"))
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
	if c.Agent.MaxConcurrent < 1 {
		errs = append(errs, errors.New("agent.max_concurrent must be >= 1"))
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
