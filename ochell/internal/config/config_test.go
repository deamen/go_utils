package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrecedence(t *testing.T) {
	t.Setenv("TEST_JIRA_SECRET", "from-env")
	p := writeYAML(t, `
http: { address: 127.0.0.1, port: 9000 }
agent:
  command: claude
  args: ["-p", "{{.Key}}"]
  timeout: 30m
sources:
  jira_webhook: { enabled: true, secret: "${TEST_JIRA_SECRET}", bot_account_id: bot }
`)
	cfg, err := Load("serve", []string{"--config", p, "--http-port", "9100", "--agent-arg", "--print", "--agent-arg", "{{.Key}}"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Address != "127.0.0.1" {
		t.Errorf("yaml address lost: %q", cfg.HTTP.Address)
	}
	if cfg.HTTP.Port != 9100 {
		t.Errorf("flag should override yaml port, got %d", cfg.HTTP.Port)
	}
	if cfg.HTTPS.Port != 8443 {
		t.Errorf("default https port lost: %d", cfg.HTTPS.Port)
	}
	if cfg.Agent.Timeout != 30*time.Minute {
		t.Errorf("yaml duration not applied: %s", cfg.Agent.Timeout)
	}
	if got := strings.Join(cfg.Agent.Args, " "); got != "--print {{.Key}}" {
		t.Errorf("repeatable flag should replace yaml args, got %q", got)
	}
	if cfg.Sources.JiraWebhook.Secret != "from-env" {
		t.Errorf("env expansion failed: %q", cfg.Sources.JiraWebhook.Secret)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestUnsetFlagsKeepYAML(t *testing.T) {
	p := writeYAML(t, "http: { port: 9000 }\nagent: { args: [a, b] }\n")
	cfg, err := Load("serve", []string{"-config=" + p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Port != 9000 || strings.Join(cfg.Agent.Args, ",") != "a,b" {
		t.Errorf("yaml values overridden by flag defaults: port=%d args=%v", cfg.HTTP.Port, cfg.Agent.Args)
	}
}

func TestUnknownYAMLKeyRejected(t *testing.T) {
	p := writeYAML(t, "htp: { port: 9000 }\n")
	if _, err := Load("serve", []string{"--config", p}, nil); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestValidate(t *testing.T) {
	cfg := Default()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "no source enabled") {
		t.Fatalf("expected no source error, got %v", err)
	}
	cfg.Sources.Linear.Enabled = true
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Path = cfg.Sources.Linear.Path
	cfg.HTTPS.Enabled = true
	err = cfg.Validate()
	for _, want := range []string{"linear.secret", "header and token", "share path", "cert_file"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("expected %q in %v", want, err)
		}
	}
}

func TestAdapterValidation(t *testing.T) {
	cfg := Default()
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = "t"
	if cfg.Agent.Adapter != "plain" {
		t.Errorf("default adapter = %q, want plain", cfg.Agent.Adapter)
	}
	cfg.Agent.Adapter = "telepathy"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "agent.adapter") {
		t.Errorf("unknown adapter: got %v", err)
	}
	cfg.Agent.Adapter = "claude"
	if err := cfg.Validate(); err != nil {
		t.Errorf("claude adapter with the prompt on stdin: %v", err)
	}
	cfg.Agent.PromptVia = "arg"
	cfg.Agent.Args = []string{"-p", "{{.Prompt}}"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "claude requires prompt_via: stdin") {
		t.Errorf("claude adapter with prompt_via arg: got %v", err)
	}
}

// A prompt template that does not tell the agent to write its result file
// would make every run end without a result.
func TestPromptTemplateMustHoldTheResultInstructions(t *testing.T) {
	cfg := Default()
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = "t"
	if !strings.Contains(cfg.Agent.PromptTemplate, "{{.ResultInstructions}}") {
		t.Fatal("the default prompt template lacks {{.ResultInstructions}}")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default configuration: %v", err)
	}
	cfg.Agent.PromptTemplate = "Fix {{.Key}}."
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "{{.ResultInstructions}}") {
		t.Errorf("template without the instructions: got %v", err)
	}
	// The run context is required for the same reason: a custom template
	// must not lose what only ochell knows.
	cfg.Agent.PromptTemplate = "Fix {{.Key}}.\n{{ .ResultInstructions }}"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "{{.RunContext}}") {
		t.Errorf("template without the run context: got %v", err)
	}
	if !strings.Contains(Default().Agent.PromptTemplate, "{{.RunContext}}") {
		t.Error("the default prompt template lacks {{.RunContext}}")
	}
	cfg.Agent.PromptTemplate = "Fix {{.Key}}.\n{{.RunContext}}\n{{ .ResultInstructions }}"
	if err := cfg.Validate(); err != nil {
		t.Errorf("template with the instructions and the run context: %v", err)
	}
	cfg.Agent.RunDir = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "agent.run_dir") {
		t.Errorf("empty run_dir: got %v", err)
	}
}

func TestRepoFor(t *testing.T) {
	cfg := Default()
	cfg.Repos = []Repo{
		{Source: "jira", Project: "DEV", Label: "Frontend", Repo: "web"},
		{Source: "jira", Project: "DEV", Repo: "backend"},
		{Source: "linear", Project: "ENG", Repo: "engine"},
		{Project: "DOCS", Repo: "docs"},
	}
	for _, c := range []struct {
		source, key string
		labels      []string
		want        string
	}{
		{"jira", "DEV-42", nil, "backend"},
		{"jira", "dev-42", nil, "backend"},
		{"jira", "DEV-42", []string{"urgent", "frontend"}, "web"},
		{"jira", "DEV-42", []string{"urgent"}, "backend"},
		{"linear", "ENG-1", nil, "engine"},
		{"linear", "DEV-1", nil, ""},    // the DEV entries are for Jira
		{"jira", "ENG-1", nil, ""},      // and ENG is for Linear
		{"jira", "DOCS-3", nil, "docs"}, // an entry without a source
		{"linear", "DOCS-3", nil, "docs"},
		{"jira", "DEVOPS-1", nil, ""},  // not a prefix match
		{"jira", "MY-PROJ-5", nil, ""}, // the project is MY-PROJ
		{"linear", "session-0d9a", nil, ""},
	} {
		got, ok := cfg.RepoFor(c.source, c.key, c.labels)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("RepoFor(%s, %s, %v) = %q, %v; want %q", c.source, c.key, c.labels, got, ok, c.want)
		}
	}
	// "*" catches what the entries before it did not.
	cfg.Repos = append(cfg.Repos, Repo{Project: "*", Repo: "everything-else"})
	if got, ok := cfg.RepoFor("jira", "OPS-1", nil); !ok || got != "everything-else" {
		t.Errorf("catch-all: %q, %v", got, ok)
	}
	if got, _ := cfg.RepoFor("jira", "DEV-1", nil); got != "backend" {
		t.Errorf("an earlier entry must win over the catch-all: %q", got)
	}
	if ProjectOf("MY-PROJ-5") != "MY-PROJ" || ProjectOf("nodash") != "nodash" {
		t.Error("ProjectOf")
	}
}

func TestRepoValidation(t *testing.T) {
	cfg := Default()
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = "t"
	cfg.Repos = []Repo{{Source: "jira", Project: "DEV", Repo: "git@example.com:org/backend.git"}, {Project: "*", Repo: "https://example.com/org/misc.git"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid repos: %v", err)
	}
	cfg.Repos = []Repo{{Source: "github", Project: "DEV", Repo: "x"}, {Repo: "x"}, {Project: "DEV"}, {Project: "DEV", Repo: "x y"}}
	err := cfg.Validate()
	for _, want := range []string{"repos[0].source", "repos[1].project", "repos[2].repo", "repos[3].repo"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("expected %q in %v", want, err)
		}
	}
}

func TestWorkspaceValidation(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		cfg.Agent.Workdir = "/work/{{.Source}}/{{.Key}}"
		cfg.Workspace.Root = "/work"
		cfg.Workspace.Cleanup = true
		cfg.Workspace.Hooks.AfterCreate = []string{"git", "clone", "{{.Repo}}", "."}
		return cfg
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid workspace settings: %v", err)
	}
	if d := Default().Workspace; d.Branch != "bot/{{.Key}}" || d.HookTimeout <= 0 || d.Cleanup || d.Root != "" {
		t.Errorf("default workspace = %+v", d)
	}
	for want, change := range map[string]func(*Config){
		"workspace.root must be an absolute path":          func(c *Config) { c.Workspace.Root = "work" },
		"workspace.cleanup requires workspace.root":        func(c *Config) { c.Workspace.Root = "" },
		"workspace.cleanup requires agent.workdir":         func(c *Config) { c.Agent.Workdir = "/work/shared" },
		"workspace.branch is required":                     func(c *Config) { c.Workspace.Branch = "" },
		"workspace.hook_timeout must be positive":          func(c *Config) { c.Workspace.HookTimeout = 0 },
		"workspace.hooks.before_run: the command is empty": func(c *Config) { c.Workspace.Hooks.BeforeRun = []string{"", "x"} },
		"workspace.hooks.after_create: agent.launcher systemd requires the command to be an absolute path": func(c *Config) {
			c.Agent.Launcher, c.Agent.Command, c.Agent.RunDir = "systemd", "/usr/local/bin/claude", "/work/runs"
		},
	} {
		cfg := base()
		change(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("expected %q in %v", want, err)
		}
	}
}

func TestAgentEnvValidation(t *testing.T) {
	p := writeYAML(t, `
agent:
  env_pass: [PATH, "BAD NAME"]
  env: { "A=B": x, GOOD_1: y }
sources:
  jira_automation: { enabled: true, token: t }
`)
	cfg, err := Load("serve", []string{"--config", p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{`agent.env_pass: "BAD NAME"`, `agent.env: "A=B"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "GOOD_1") || strings.Contains(err.Error(), `"PATH"`) {
		t.Errorf("valid names rejected:\n%v", err)
	}

	cfg, err = Load("serve", []string{"--agent-env-pass", "PATH", "--agent-env-pass", "ANTHROPIC_API_KEY"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Agent.EnvPass, ","); got != "PATH,ANTHROPIC_API_KEY" {
		t.Errorf("flag should replace the default env_pass, got %q", got)
	}
	if got := Default().Agent.EnvPass; len(got) != len(DefaultEnvPass) {
		t.Errorf("default env_pass changed by a flag: %v", got)
	}
}

func TestPromptOnStdinByDefault(t *testing.T) {
	cfg := Default()
	if cfg.Agent.PromptVia != "stdin" {
		t.Errorf("default prompt_via = %q, want stdin", cfg.Agent.PromptVia)
	}
	for _, a := range cfg.Agent.Args {
		if strings.Contains(a, "Prompt") {
			t.Errorf("default args carry the prompt: %q", cfg.Agent.Args)
		}
	}
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = "t"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default agent settings must be valid: %v", err)
	}

	// A configuration written for the old default must not send the prompt
	// both ways without anyone noticing.
	cfg.Agent.Args = []string{"-p", "{{.Prompt}}"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "prompt_via is stdin") {
		t.Errorf("stdin with {{.Prompt}} in args: got %v", err)
	}
	cfg.Agent.PromptVia = "arg"
	if err := cfg.Validate(); err != nil {
		t.Errorf("arg with {{.Prompt}} in args must stay valid: %v", err)
	}
}

// podmanLauncher makes c a valid configuration with the podman launcher.
func podmanLauncher(c *Config) {
	c.Agent.Launcher = "podman"
	c.Agent.Podman.Image = "registry.example.com/agent:7"
	c.Agent.Workdir = "/work/{{.Source}}/{{.Key}}"
}

func TestPodmanLauncherValidation(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		cfg.Agent.Launcher = "podman"
		cfg.Agent.Podman.Image = "registry.example.com/agent:7"
		cfg.Agent.Workdir = "/work/{{.Source}}/{{.Key}}"
		return cfg
	}
	// What the systemd launcher forbids is allowed here: podman changes
	// nothing in the arguments, and the command is found in the image.
	cfg := base()
	cfg.Agent.PromptVia = "arg"
	cfg.Agent.Args = []string{"-p", "{{.Prompt}}"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid podman configuration: %v", err)
	}
	cases := map[string]struct {
		change func(c *Config)
		want   string
	}{
		"no image":             {func(c *Config) { c.Agent.Podman.Image = "" }, "agent.podman.image"},
		"no command":           {func(c *Config) { c.Agent.Podman.Command = "" }, "agent.podman.command"},
		"no state directory":   {func(c *Config) { c.Agent.Podman.StateDir = "" }, "agent.podman.state_dir"},
		"unknown pull policy":  {func(c *Config) { c.Agent.Podman.Pull = "sometimes" }, "agent.podman.pull must be"},
		"default workdir":      {func(c *Config) { c.Agent.Workdir = Default().Agent.Workdir }, "agent.workdir to be an absolute path"},
		"relative workdir":     {func(c *Config) { c.Agent.Workdir = "work/{{.Key}}" }, "agent.workdir to be an absolute path"},
		"one workdir for all":  {func(c *Config) { c.Agent.Workdir = "/work/all" }, "agent.workdir to contain {{.Key}}"},
		"empty extra argument": {func(c *Config) { c.Agent.Podman.Args = []string{"--memory=1g", ""} }, "agent.podman.args"},
	}
	for name, c := range cases {
		cfg := base()
		c.change(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, c.want)
		}
	}

	p := writeYAML(t, `
agent:
  launcher: podman
  workdir: /work/{{.Source}}/{{.Key}}
  podman:
    image: localhost/agent:1
    pull: missing
    env_file: /etc/ochell/agent.env
    args: [--memory=4g, --cpus=2]
`)
	cfg, err := Load("serve", []string{"--config", p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pm := cfg.Agent.Podman
	if pm.Command != "podman" || pm.StateDir != "state" {
		t.Errorf("defaults lost: %+v", pm)
	}
	if pm.Image != "localhost/agent:1" || pm.Pull != "missing" || pm.EnvFile != "/etc/ochell/agent.env" || strings.Join(pm.Args, " ") != "--memory=4g --cpus=2" {
		t.Errorf("podman settings = %+v", pm)
	}
	// A setting that ochell does not know stays an error.
	p = writeYAML(t, "agent:\n  podman:\n    volumes: [/etc:/etc]\n")
	if _, err := Load("serve", []string{"--config", p}, nil); err == nil {
		t.Error("an unknown setting of agent.podman was accepted")
	}
}

func TestSystemdLauncherValidation(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		cfg.Agent.Launcher = "systemd"
		cfg.Agent.Command = "/usr/local/bin/claude"
		cfg.Agent.Workdir = "/work/{{.Source}}/{{.Key}}"
		cfg.Agent.RunDir = "/work/runs"
		return cfg
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid systemd configuration: %v", err)
	}
	cfg := base()
	cfg.Agent.PromptVia = "arg"
	cfg.Agent.Args = []string{"-p", "{{.Prompt}}"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "requires prompt_via: stdin") {
		t.Errorf("prompt_via arg with the systemd launcher: got %v", err)
	}
	cfg = base()
	cfg.Agent.Command = "claude"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("relative command with the systemd launcher: got %v", err)
	}
	// The default workdir is ".", which the launch script refuses.
	for _, dir := range []string{Default().Agent.Workdir, "work/{{.Key}}"} {
		cfg = base()
		cfg.Agent.Workdir = dir
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "agent.workdir to be an absolute path") {
			t.Errorf("workdir %q with the systemd launcher: got %v", dir, err)
		}
	}
	cfg = base()
	cfg.Agent.RunDir = "runs"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "agent.run_dir to be an absolute path") {
		t.Errorf("relative run_dir with the systemd launcher: got %v", err)
	}
	cfg = base()
	cfg.Agent.Systemd.StopCommand = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "stop_command") {
		t.Errorf("missing stop_command: got %v", err)
	}
	cfg = base()
	cfg.Agent.Launcher = "docker"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "direct, systemd or podman") {
		t.Errorf("unknown launcher: got %v", err)
	}

	p := writeYAML(t, `
agent:
  launcher: systemd
  command: /usr/local/bin/claude
  stop_grace: 20s
  systemd:
    launch_command: [sudo, -n, /opt/ochell-launch]
`)
	cfg, err := Load("serve", []string{"--config", p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Agent.Systemd.LaunchCommand, " "); got != "sudo -n /opt/ochell-launch" {
		t.Errorf("launch_command = %q", got)
	}
	if got := strings.Join(cfg.Agent.Systemd.StopCommand, " "); got != "sudo -n /usr/local/libexec/ochell/ochell-stop" {
		t.Errorf("default stop_command lost: %q", got)
	}
	if cfg.Agent.StopGrace != 20*time.Second {
		t.Errorf("stop_grace = %s", cfg.Agent.StopGrace)
	}
}

func TestJiraAPI(t *testing.T) {
	ok := JiraAPI{BaseURL: "https://example.atlassian.net", Email: "bot@example.com", Token: "t"}
	for name, tc := range map[string]struct {
		change func(*JiraAPI)
		want   string
	}{
		"complete":        {func(*JiraAPI) {}, ""},
		"not configured":  {func(j *JiraAPI) { *j = JiraAPI{} }, ""},
		"no token":        {func(j *JiraAPI) { j.Token = "" }, "requires email and token"},
		"no email":        {func(j *JiraAPI) { j.Email = "" }, "requires email and token"},
		"not an address":  {func(j *JiraAPI) { j.BaseURL = "example.atlassian.net" }, "base_url must be"},
		"with a password": {func(j *JiraAPI) { j.BaseURL = "https://bot:secret@example.atlassian.net" }, "base_url must be"},
		"only a token":    {func(j *JiraAPI) { j.BaseURL = "" }, "base_url is not"},
	} {
		j := ok
		tc.change(&j)
		err := j.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
	if (JiraAPI{}).Enabled() || !ok.Enabled() {
		t.Error("Enabled must follow base_url")
	}
}

func TestRetryValidation(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		return cfg
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	for name, tc := range map[string]struct {
		change func(*Config)
		want   string
	}{
		"bad pattern":       {func(c *Config) { c.Agent.Retry.Patterns = []string{"rate limit", "("} }, "retry.patterns[1]"},
		"empty pattern":     {func(c *Config) { c.Agent.Retry.Patterns = []string{""} }, "retry.patterns[0]"},
		"no backoff":        {func(c *Config) { c.Agent.Retry.Backoff = 0 }, "backoff must be positive"},
		"max below backoff": {func(c *Config) { c.Agent.Retry.MaxBackoff = time.Second }, "max_backoff not below"},
		"negative stall":    {func(c *Config) { c.Agent.StallTimeout = -time.Second }, "stall_timeout"},
		"negative repeats":  {func(c *Config) { c.Agent.Watchdog.Repeats = -1 }, "watchdog.repeats"},
		"one repeat":        {func(c *Config) { c.Agent.Watchdog.Repeats = 1 }, "watchdog.repeats"},
		"watchdog on":       {func(c *Config) { c.Agent.Watchdog.Repeats = 2 }, ""},
		// Without patterns nothing is retried, and the backoff is not looked at.
		"retry turned off": {func(c *Config) { c.Agent.Retry = Retry{} }, ""},
	} {
		cfg := base()
		tc.change(cfg)
		err := cfg.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
	// An empty list in the file turns the retry off.
	p := writeYAML(t, "agent: { retry: { patterns: [] } }\n")
	cfg, err := Load("serve", []string{"--config", p}, nil)
	if err != nil || len(cfg.Agent.Retry.Patterns) != 0 {
		t.Errorf("patterns: [] gave %q, %v", cfg.Agent.Retry.Patterns, err)
	}
}

// The example file is what people copy: it must load, be valid, and show
// the defaults it claims to show.
func TestExampleFile(t *testing.T) {
	for _, name := range []string{"JIRA_WEBHOOK_SECRET", "JIRA_AUTOMATION_TOKEN", "JIRA_API_TOKEN", "LINEAR_WEBHOOK_SECRET", "LINEAR_CLIENT_ID", "LINEAR_CLIENT_SECRET", "NGROK_API_KEY"} {
		t.Setenv(name, "x")
	}
	cfg := Default()
	if err := LoadFile(cfg, "../../examples/config.yaml"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("examples/config.yaml is not valid:\n%v", err)
	}
	def := Default()
	if !slices.Equal(cfg.Agent.Retry.Patterns, def.Agent.Retry.Patterns) || cfg.Agent.Retry.Backoff != def.Agent.Retry.Backoff || cfg.Agent.Retry.MaxBackoff != def.Agent.Retry.MaxBackoff {
		t.Errorf("agent.retry in the example is not the default: %+v", cfg.Agent.Retry)
	}
}

func TestPollerSettings(t *testing.T) {
	cfg := Default()
	if cfg.Poller.Interval != 5*time.Minute {
		t.Errorf("default poller.interval = %s, want 5m", cfg.Poller.Interval)
	}
	p := writeYAML(t, "poller: { interval: 0s }\n")
	cfg, err := Load("serve", []string{"--config", p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Poller.Interval != 0 {
		t.Errorf("interval 0s in the file gave %s", cfg.Poller.Interval)
	}
	cfg, err = Load("serve", []string{"--config", p, "--poll-interval", "90s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Poller.Interval != 90*time.Second {
		t.Errorf("--poll-interval gave %s", cfg.Poller.Interval)
	}
	cfg.Sources.JiraAutomation.Enabled, cfg.Sources.JiraAutomation.Token = true, "t"
	cfg.Poller.Interval = -time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "poller.interval") {
		t.Errorf("a negative interval: %v", err)
	}
}

func TestAPISettings(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		return cfg
	}
	cfg := base()
	cfg.API = API{Enabled: true, Token: "0123456789abcdef", PublicURL: "https://ochell.example.com"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a valid API: %v", err)
	}
	for name, c := range map[string]struct {
		api  API
		want string
	}{
		"no token":        {API{Enabled: true}, "api.token is required"},
		"short token":     {API{Enabled: true, Token: "short"}, "at least 16 characters"},
		"bad address":     {API{Enabled: true, Token: "0123456789abcdef", PublicURL: "ochell.example.com"}, "api.public_url must be an address"},
		"address, no API": {API{PublicURL: "https://ochell.example.com"}, "the status API is not enabled"},
	} {
		cfg := base()
		cfg.API = c.api
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one with %q", name, err, c.want)
		}
	}
}

func TestTicketToolsSettings(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraWebhook = JiraWebhook{Enabled: true, Path: "/webhooks/jira", Secret: "s", BotAccountID: "712020:bot", MaxSkew: time.Hour}
		cfg.Sources.JiraAPI = JiraAPI{BaseURL: "https://example.atlassian.net", Email: "bot@example.com", Token: "t"}
		cfg.TicketTools.Enabled = true
		return cfg
	}
	cfg := base()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid ticket tools: %v", err)
	}
	// The address for an agent: the HTTP listener, on the loopback address
	// when it takes every address.
	for name, c := range map[string]struct {
		change func(*Config)
		want   string
	}{
		"every address": {func(*Config) {}, "http://127.0.0.1:8080/mcp"},
		"one address":   {func(c *Config) { c.HTTP.Address, c.HTTP.Port = "10.0.0.5", 9000 }, "http://10.0.0.5:9000/mcp"},
		"IPv6":          {func(c *Config) { c.HTTP.Address = "::" }, "http://127.0.0.1:8080/mcp"},
		"a name":        {func(c *Config) { c.HTTP.Address = "localhost" }, "http://localhost:8080/mcp"},
		"set":           {func(c *Config) { c.TicketTools.URL = "https://ochell.example.com/mcp" }, "https://ochell.example.com/mcp"},
		// In a container the loopback address is the container's own.
		"podman, every address": {func(c *Config) { podmanLauncher(c) }, "http://host.containers.internal:8080/mcp"},
		"podman, one address":   {func(c *Config) { podmanLauncher(c); c.HTTP.Address = "10.0.0.5" }, "http://10.0.0.5:8080/mcp"},
		"podman, set": {func(c *Config) {
			podmanLauncher(c)
			c.HTTP.Address, c.TicketTools.URL = "127.0.0.1", "http://10.0.2.2:8080/mcp"
		},
			"http://10.0.2.2:8080/mcp"},
	} {
		cfg := base()
		c.change(cfg)
		if err := cfg.Validate(); err != nil || cfg.TicketToolsURL() != c.want {
			t.Errorf("%s: %q, %v; want %q", name, cfg.TicketToolsURL(), err, c.want)
		}
	}
	for name, c := range map[string]struct {
		change func(*Config)
		want   string
	}{
		"no http listener": {func(c *Config) {
			c.HTTP.Enabled = false
			c.HTTPS = Listener{Enabled: true, Address: "0.0.0.0", Port: 8443, CertFile: "c", KeyFile: "k"}
		}, "ticket_tools.url is required when the http listener is off"},
		"podman, a loopback listener": {func(c *Config) { podmanLauncher(c); c.HTTP.Address = "127.0.0.1" }, "which a container does not reach"},
		"podman, localhost":           {func(c *Config) { podmanLauncher(c); c.HTTP.Address = "localhost" }, "which a container does not reach"},
		"another path":                {func(c *Config) { c.TicketTools.URL = "http://127.0.0.1:8080/tools" }, "with the path /mcp"},
		"not a URL":                   {func(c *Config) { c.TicketTools.URL = "127.0.0.1:8080/mcp" }, "ticket_tools.url must be"},
		"a password":                  {func(c *Config) { c.TicketTools.URL = "http://u:p@127.0.0.1:8080/mcp" }, "ticket_tools.url must be"},
		"no Jira API":                 {func(c *Config) { c.Sources.JiraAPI = JiraAPI{} }, "ticket_tools needs sources.jira_api"},
		"no bot":                      {func(c *Config) { c.Sources.JiraWebhook.BotAccountID = "" }, "ticket_tools needs sources.jira_webhook.bot_account_id"},
		"no Linear app":               {func(c *Config) { c.Sources.Linear.Enabled, c.Sources.Linear.Secret = true, "s" }, "ticket_tools needs the Linear app"},
		"address, off": {func(c *Config) {
			c.TicketTools = TicketTools{URL: "http://127.0.0.1:8080/mcp"}
		}, "ticket_tools.enabled is not"},
	} {
		cfg := base()
		c.change(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one with %q", name, err, c.want)
		}
	}
	// The default prompt names the ticket tool that the run has.
	if !strings.Contains(DefaultPromptTemplate, `{{if .TicketTools}}Read the full ticket with the tool get_ticket of the MCP server "ochell"{{else}}Use twg`) {
		t.Error("the default prompt does not tell a run with the ticket tools to use them")
	}
}

func TestGitHubSettings(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		return cfg
	}
	cfg := base()
	if cfg.GitHub.Enabled() || cfg.GitHub.PollInterval != 2*time.Minute {
		t.Errorf("default = %+v", cfg.GitHub)
	}
	cfg.GitHub.Token, cfg.GitHub.APIURL, cfg.GitHub.BotLogin = "t", "https://ghe.example.com/api/v3", "bot"
	if err := cfg.Validate(); err != nil || !cfg.GitHub.Enabled() {
		t.Errorf("a valid GitHub access: %v", err)
	}
	for name, c := range map[string]struct {
		gh   GitHub
		want string
	}{
		"no interval":     {GitHub{Token: "t"}, "github.poll_interval must be positive"},
		"bad address":     {GitHub{Token: "t", PollInterval: time.Minute, APIURL: "ghe.example.com"}, "github.api_url must be the address of the API"},
		"login, no token": {GitHub{BotLogin: "bot", PollInterval: time.Minute}, "bot_login is set but token is not"},
	} {
		cfg := base()
		cfg.GitHub = c.gh
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one with %q", name, err, c.want)
		}
	}
}

func TestRetentionSettings(t *testing.T) {
	cfg := Default()
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = "t"
	if cfg.Retention.Logs != 30*24*time.Hour || cfg.Retention.Interval != time.Hour {
		t.Errorf("default = %+v", cfg.Retention)
	}
	cfg.Retention.Logs = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("no limit: %v", err)
	}
	cfg.Retention.Logs = -time.Hour
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "retention.logs must not be negative") {
		t.Errorf("a negative limit: %v", err)
	}
	cfg.Retention = Retention{Logs: time.Hour}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "retention.interval must be positive") {
		t.Errorf("no interval: %v", err)
	}
}

func TestBackupSettings(t *testing.T) {
	cfg := Default()
	cfg.Sources.JiraAutomation.Enabled = true
	cfg.Sources.JiraAutomation.Token = "t"
	if cfg.Backup.Dir != "" || cfg.Backup.Interval != 24*time.Hour || cfg.Backup.Keep != 7 {
		t.Errorf("default = %+v", cfg.Backup)
	}
	cfg.Backup.Dir = "/var/backups/ochell"
	if err := cfg.Validate(); err != nil {
		t.Errorf("a valid backup: %v", err)
	}
	cfg.Backup.Interval = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "backup.interval must be positive") {
		t.Errorf("no interval: %v", err)
	}
	cfg.Backup = Backup{Keep: -1}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "backup.keep must not be negative") {
		t.Errorf("a negative keep: %v", err)
	}
}

func TestMetricsAndTokenSettings(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		return cfg
	}
	cfg := base()
	cfg.Metrics = Metrics{Enabled: true, Token: "0123456789abcdef"}
	cfg.Agent.TokenExpires = "2027-11-13"
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid settings: %v", err)
	}
	// The token works through that day.
	if at, err := cfg.Agent.TokenExpiry(); err != nil || !at.Equal(time.Date(2027, 11, 14, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("TokenExpiry = %v, %v", at, err)
	}
	if at, err := base().Agent.TokenExpiry(); err != nil || !at.IsZero() || base().Agent.TokenWarnDays != 30 {
		t.Errorf("without a date: %v, %v", at, err)
	}
	for name, c := range map[string]struct {
		change func(*Config)
		want   string
	}{
		"no metrics token": {func(c *Config) { c.Metrics.Enabled = true }, "metrics.token is required"},
		"bad date":         {func(c *Config) { c.Agent.TokenExpires = "13/11/2027" }, "agent.token_expires must be a date"},
		"negative days":    {func(c *Config) { c.Agent.TokenWarnDays = -1 }, "agent.token_warn_days must not be negative"},
	} {
		cfg := base()
		c.change(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one with %q", name, err, c.want)
		}
	}
}

func TestWorkflowSettings(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Sources.JiraAutomation.Enabled = true
		cfg.Sources.JiraAutomation.Token = "t"
		return cfg
	}
	cfg := base()
	if cfg.Workflow.Enabled {
		t.Error("a repository's WORKFLOW.md must not be read by default")
	}
	cfg.GitHub.Token = "token"
	cfg.Workflow = Workflow{Enabled: true, AllowHooks: true, ReviewStatuses: []string{"In Review"}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a valid workflow section: %v", err)
	}
	for name, c := range map[string]struct {
		change func(*Config)
		want   string
	}{
		"no access to GitHub":  {func(c *Config) { c.GitHub.Token = "" }, "workflow.enabled requires github.token"},
		"an empty status":      {func(c *Config) { c.Workflow.ReviewStatuses = []string{" "} }, "workflow.review_statuses: an empty entry"},
		"hooks without enable": {func(c *Config) { c.Workflow.Enabled = false }, "allow_hooks or review_statuses is set but enabled is not"},
	} {
		cfg := base()
		cfg.GitHub.Token = "token"
		cfg.Workflow = Workflow{Enabled: true, AllowHooks: true}
		c.change(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one with %q", name, err, c.want)
		}
	}
}
