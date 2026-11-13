package jira

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const bot = "712020:digital-employee"

func TestParseWebhookAssigned(t *testing.T) {
	body, err := os.ReadFile("../../../testdata/jira-issue-assigned.json")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := ParseWebhook(body, bot)
	if err != nil {
		t.Fatal(err)
	}
	if tk.Key != "DEV-42" || tk.URL != "https://example.atlassian.net/browse/DEV-42" || tk.Summary == "" {
		t.Errorf("unexpected ticket %+v", tk)
	}
	if _, err := ParseWebhook(body, "someone-else"); !errors.Is(err, ErrIgnored) {
		t.Errorf("assignment to another user should be ignored, got %v", err)
	}
	// An update that does not touch the assignee must not re-trigger.
	other := strings.Replace(string(body), `"field": "assignee"`, `"field": "status"`, 1)
	other = strings.Replace(other, `"fieldId": "assignee"`, `"fieldId": "status"`, 1)
	if _, err := ParseWebhook([]byte(other), bot); !errors.Is(err, ErrIgnored) {
		t.Errorf("non-assignee change should be ignored, got %v", err)
	}
}

func TestParseWebhookCreated(t *testing.T) {
	body := `{"webhookEvent":"jira:issue_created","issue":{"key":"DEV-1","self":"https://x.atlassian.net/rest/api/2/issue/1","fields":{"summary":"s","assignee":{"accountId":"` + bot + `"}}}}`
	if _, err := ParseWebhook([]byte(body), bot); err != nil {
		t.Fatal(err)
	}
	unassigned := `{"webhookEvent":"jira:issue_created","issue":{"key":"DEV-1","fields":{"assignee":null}}}`
	if _, err := ParseWebhook([]byte(unassigned), bot); !errors.Is(err, ErrIgnored) {
		t.Errorf("unassigned create should be ignored, got %v", err)
	}
	if _, err := ParseWebhook([]byte(`{"webhookEvent":"comment_created","issue":{"key":"DEV-1"}}`), bot); !errors.Is(err, ErrIgnored) {
		t.Errorf("other events should be ignored, got %v", err)
	}
	if _, err := ParseWebhook([]byte(`not json`), bot); err == nil || errors.Is(err, ErrIgnored) {
		t.Errorf("bad json should be an error, got %v", err)
	}
}

func TestParseAutomation(t *testing.T) {
	body, err := os.ReadFile("../../../testdata/jira-automation.json")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := ParseAutomation(body, bot)
	if err != nil || tk.Key != "DEV-42" {
		t.Fatalf("got %+v, %v", tk, err)
	}
	if _, err := ParseAutomation(body, "other"); !errors.Is(err, ErrIgnored) {
		t.Errorf("wrong assignee should be ignored, got %v", err)
	}
	jiraFormat := `{"issue":{"key":"DEV-7","self":"https://x.atlassian.net/rest/api/2/issue/7","fields":{"summary":"s","assignee":{"accountId":"` + bot + `"}}}}`
	tk, err = ParseAutomation([]byte(jiraFormat), bot)
	if err != nil || tk.Key != "DEV-7" || tk.URL != "https://x.atlassian.net/browse/DEV-7" {
		t.Fatalf("jira format: got %+v, %v", tk, err)
	}
	if _, err := ParseAutomation([]byte(`{}`), bot); err == nil {
		t.Error("missing key should fail")
	}
}

// With the bot's account id configured, a payload that names no assignee
// must not start a run.
func TestParseAutomationRequiresAssignee(t *testing.T) {
	for name, body := range map[string]string{
		"field missing":        `{"issueKey":"DEV-1","summary":"s"}`,
		"field empty":          `{"issueKey":"DEV-1","assigneeAccountId":""}`,
		"field blank":          `{"issueKey":"DEV-1","assigneeAccountId":"  "}`,
		"jira format, null":    `{"issue":{"key":"DEV-1","fields":{"summary":"s","assignee":null}}}`,
		"jira format, missing": `{"issue":{"key":"DEV-1","fields":{"summary":"s"}}}`,
		"jira format, empty":   `{"issue":{"key":"DEV-1","fields":{"assignee":{"accountId":""}}}}`,
	} {
		tk, err := ParseAutomation([]byte(body), bot)
		if !errors.Is(err, ErrNoAssignee) || errors.Is(err, ErrIgnored) || tk != nil {
			t.Errorf("%s: got %+v, %v; want ErrNoAssignee", name, tk, err)
		}
	}
	// Without a configured bot the rule alone decides, as before.
	if tk, err := ParseAutomation([]byte(`{"issueKey":"DEV-1"}`), ""); err != nil || tk.Key != "DEV-1" {
		t.Errorf("no bot configured: got %+v, %v", tk, err)
	}
}
