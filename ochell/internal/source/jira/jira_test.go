package jira

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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

// Labels and components are read where the payload has them, for the
// repository mapping.
func TestLabels(t *testing.T) {
	hook := `{"webhookEvent":"jira:issue_created","issue":{"key":"DEV-1","fields":{
		"assignee":{"accountId":"bot"},"labels":["urgent","frontend"],"components":[{"name":"Checkout"},{"name":""}]}}}`
	tk, err := ParseWebhook([]byte(hook), "bot")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(tk.Labels, ","); got != "urgent,frontend,Checkout" {
		t.Errorf("webhook labels = %q", got)
	}
	for body, want := range map[string]string{
		`{"issueKey":"DEV-1","labels":["a","b"]}`:                                         "a,b",
		`{"issueKey":"DEV-1","labels":"a, b ,,c"}`:                                        "a,b,c",
		`{"issueKey":"DEV-1","labels":""}`:                                                "",
		`{"issueKey":"DEV-1"}`:                                                            "",
		`{"issue":{"key":"DEV-1","fields":{"labels":["x"],"components":[{"name":"Y"}]}}}`: "x,Y",
	} {
		tk, err := ParseAutomation([]byte(body), "")
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got := strings.Join(tk.Labels, ","); got != want {
			t.Errorf("%s: labels = %q, want %q", body, got, want)
		}
	}
	if _, err := ParseAutomation([]byte(`{"issueKey":"DEV-1","labels":7}`), ""); err == nil {
		t.Error("labels that are neither a list nor a text must be refused")
	}
}

func TestCheckTimestamp(t *testing.T) {
	now := time.UnixMilli(1760152365200)
	body := func(ts string) []byte { return []byte(`{"timestamp":` + ts + `,"webhookEvent":"jira:issue_updated"}`) }
	at := func(d time.Duration) []byte { return body(strconv.FormatInt(now.Add(d).UnixMilli(), 10)) }
	for name, c := range map[string]struct {
		body  []byte
		stale bool
	}{
		"now":             {at(0), false},
		"inside, past":    {at(-59 * time.Minute), false},
		"inside, future":  {at(59 * time.Minute), false},
		"too old":         {at(-61 * time.Minute), true},
		"a day old":       {at(-24 * time.Hour), true},
		"from the future": {at(61 * time.Minute), true},
		"missing":         {[]byte(`{"webhookEvent":"jira:issue_updated"}`), true},
		"null":            {body("null"), true},
		"seconds, not ms": {body(strconv.FormatInt(now.Unix(), 10)), true},
	} {
		err := CheckTimestamp(c.body, time.Hour, now)
		if c.stale != errors.Is(err, ErrStale) {
			t.Errorf("%s: got %v, want stale=%v", name, err, c.stale)
		}
	}
	// Anything that is not a number is refused as well.
	for _, body := range []string{`{"timestamp":"yesterday"}`, `{"timestamp":{}}`, `not json`} {
		if err := CheckTimestamp([]byte(body), time.Hour, now); err == nil {
			t.Errorf("%s: accepted", body)
		}
	}
}
