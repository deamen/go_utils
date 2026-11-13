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
