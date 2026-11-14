package config

import (
	"os"
	"path/filepath"
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
	cfg.Agent.PromptTemplate = "Fix {{.Key}}.\n{{ .ResultInstructions }}"
	if err := cfg.Validate(); err != nil {
		t.Errorf("template with the instructions: %v", err)
	}
	cfg.Agent.RunDir = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "agent.run_dir") {
		t.Errorf("empty run_dir: got %v", err)
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
