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
	// text/template rendered with the task (e.g. "{{.Prompt}}").
	Args []string `yaml:"args"`
	// PromptVia is "arg" (prompt referenced in Args) or "stdin".
	PromptVia      string            `yaml:"prompt_via"`
	PromptTemplate string            `yaml:"prompt_template"`
	Workdir        string            `yaml:"workdir"`
	Env            map[string]string `yaml:"env"`
	Timeout        time.Duration     `yaml:"timeout"`
	MaxConcurrent  int               `yaml:"max_concurrent"`
	QueueSize      int               `yaml:"queue_size"`
	LogDir         string            `yaml:"log_dir"`
}

type JiraWebhook struct {
	Enabled      bool   `yaml:"enabled"`
	Path         string `yaml:"path"`
	Secret       string `yaml:"secret"`
	BotAccountID string `yaml:"bot_account_id"`
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

type Config struct {
	LogLevel    string      `yaml:"log_level"`
	HTTP        Listener    `yaml:"http"`
	HTTPS       Listener    `yaml:"https"`
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

func Default() *Config {
	return &Config{
		LogLevel: "info",
		HTTP:     Listener{Enabled: true, Address: "0.0.0.0", Port: 8080},
		HTTPS:    Listener{Enabled: false, Address: "0.0.0.0", Port: 8443},
		Agent: Agent{
			Command:        "claude",
			Args:           []string{"-p", "{{.Prompt}}"},
			PromptVia:      "arg",
			PromptTemplate: DefaultPromptTemplate,
			Workdir:        ".",
			Timeout:        2 * time.Hour,
			MaxConcurrent:  1,
			QueueSize:      100,
			LogDir:         "logs",
		},
		Sources: Sources{
			JiraWebhook:    JiraWebhook{Path: "/webhooks/jira"},
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

	fs.StringVar(&c.Agent.Command, "agent-cmd", c.Agent.Command, "agent CLI command")
	fs.Var(&stringList{dst: &c.Agent.Args}, "agent-arg", "agent CLI argument, repeatable, Go template (replaces config args)")
	fs.StringVar(&c.Agent.PromptVia, "agent-prompt-via", c.Agent.PromptVia, "how the prompt is passed: arg or stdin")
	fs.StringVar(&c.Agent.Workdir, "agent-workdir", c.Agent.Workdir, "agent working directory, Go template")
	fs.DurationVar(&c.Agent.Timeout, "agent-timeout", c.Agent.Timeout, "maximum agent run time")
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
	if c.Agent.Command == "" {
		errs = append(errs, errors.New("agent.command is required"))
	}
	if c.Agent.PromptVia != "arg" && c.Agent.PromptVia != "stdin" {
		errs = append(errs, errors.New("agent.prompt_via must be arg or stdin"))
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
