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
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "direct or systemd") {
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
