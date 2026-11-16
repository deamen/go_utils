package linear_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"ochell/internal/source/linear"
	"ochell/internal/source/linear/lineartest"
	"ochell/internal/tracker"
)

func client(t *testing.T) (*linear.Client, *lineartest.Server) {
	t.Helper()
	api := lineartest.New(t, "access-1")
	c := linear.NewClient("cid", "csecret", filepath.Join(t.TempDir(), "token.json"))
	c.APIURL = api.URL
	if err := c.SaveToken(&linear.Token{AccessToken: "access-1"}); err != nil {
		t.Fatal(err)
	}
	return c, api
}

func TestAssigned(t *testing.T) {
	c, api := client(t)
	api.Add(lineartest.Issue{Key: "ENG-1", Title: "First", Labels: []string{"backend"}, DelegatedBy: "u-anna"})
	api.Add(lineartest.Issue{Key: "ENG-2", Title: "Second", DelegatedBy: "u-anna"})
	api.Add(lineartest.Issue{Key: "ENG-3", Title: "Third", DelegatedBy: "u-bob"})
	api.Add(lineartest.Issue{Key: "ENG-4", Title: "Only mentioned"})
	api.Add(lineartest.Issue{Key: "ENG-5", Title: "Closed", DelegatedBy: "u-bob"})
	api.Add(lineartest.Issue{Key: "ENG-6", Title: "Taken away", DelegatedBy: "u-bob"})
	api.Close("ENG-5")
	api.Undelegate("ENG-6")
	got, err := c.Assigned(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Three issues in pages of two.
	var keys []string
	for _, is := range got {
		keys = append(keys, is.Key)
	}
	if want := []string{"ENG-1", "ENG-2", "ENG-3"}; !slices.Equal(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	if is := got[0]; is.Title != "First" || is.URL != "https://linear.app/example/issue/ENG-1" || !slices.Equal(is.Labels, []string{"backend"}) {
		t.Errorf("first issue = %+v", is)
	}
	// A failing API is an error, never a shorter list.
	api.Fail(true)
	if got, err := c.Assigned(context.Background()); err == nil || got != nil {
		t.Errorf("Assigned against a failing API = %v, %v", got, err)
	}
}

func TestAssignerAndLookup(t *testing.T) {
	c, api := client(t)
	api.Add(lineartest.Issue{Key: "ENG-1", DelegatedBy: "u-anna", Creator: "u-carl"})
	api.Add(lineartest.Issue{Key: "ENG-2", Creator: "u-carl"})
	api.Add(lineartest.Issue{Key: "ENG-3"})
	api.Add(lineartest.Issue{Key: "ENG-4", DelegatedBy: "u-anna"})
	api.Add(lineartest.Issue{Key: "ENG-5", DelegatedBy: "u-anna"})
	api.Close("ENG-4")
	api.Undelegate("ENG-5")
	ctx := context.Background()
	for key, want := range map[string][]string{
		"ENG-1": {"u-anna", "u-anna@example.com"},
		// Never delegated: the creator is the best there is.
		"ENG-2": {"u-carl", "u-carl@example.com"},
		"ENG-3": nil,
	} {
		got, err := c.Assigner(ctx, key)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("Assigner(%s) = %q, %v; want %q", key, got, err, want)
		}
	}
	for key, want := range map[string]tracker.Status{
		"ENG-1": {},
		// Only mentioned: it was never the agent's, so it was not taken away.
		"ENG-2": {},
		"ENG-4": {Closed: true},
		"ENG-5": {Unassigned: true},
	} {
		got, err := c.Lookup(ctx, key)
		if err != nil || got != want {
			t.Errorf("Lookup(%s) = %+v, %v; want %+v", key, got, err, want)
		}
	}
	if _, err := c.Lookup(ctx, "ENG-404"); err == nil {
		t.Error("Lookup of an unknown issue gave no error")
	}
}

func TestCreateSessionOnIssue(t *testing.T) {
	c, api := client(t)
	api.Add(lineartest.Issue{Key: "ENG-1", DelegatedBy: "u-anna"})
	id, err := c.CreateSessionOnIssue(context.Background(), "ENG-1")
	if err != nil || id == "" {
		t.Fatalf("CreateSessionOnIssue = %q, %v", id, err)
	}
	if got := api.Sessions("ENG-1"); !slices.Equal(got, []string{id}) {
		t.Errorf("sessions on the issue = %q, want %q", got, id)
	}
	// The new session takes activities like any other.
	if err := c.CreateActivity(context.Background(), id, linear.ActivityThought, "Picked up ENG-1."); err != nil {
		t.Fatal(err)
	}
	if acts := api.Activities(id); len(acts) != 1 || acts[0].Body != "Picked up ENG-1." {
		t.Errorf("activities = %+v", acts)
	}
	if _, err := c.CreateSessionOnIssue(context.Background(), "ENG-404"); err == nil {
		t.Error("a session on an unknown issue gave no error")
	}
}

func TestScheduling(t *testing.T) {
	c, api := client(t)
	api.Add(lineartest.Issue{Key: "ENG-1", DelegatedBy: "u-anna", Creator: "u-carl", Priority: 2,
		Labels:    []string{"agent-ready", "old", "own"},
		LabelsBy:  map[string]string{"agent-ready": "u-anna", "own": lineartest.AppUserID},
		BlockedBy: []string{"ENG-2", "ENG-3", "ELSE-9"}})
	api.Add(lineartest.Issue{Key: "ENG-2", DelegatedBy: "u-anna", Priority: 1})
	api.Add(lineartest.Issue{Key: "ENG-3"})
	api.Add(lineartest.Issue{Key: "ENG-4"})
	api.Close("ENG-3")
	ctx := context.Background()

	got, err := c.Scheduling(ctx, "ENG-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Priority != 2 {
		t.Errorf("priority = %d, want 2", got.Priority)
	}
	// Who added each label: the actor of the last change that added it,
	// the creator for one that the issue was created with.
	want := []tracker.Label{
		{Name: "agent-ready", By: []string{"u-anna", "u-anna@example.com"}},
		{Name: "old", By: []string{"u-carl", "u-carl@example.com"}},
		{Name: "own", By: []string{lineartest.AppUserID, lineartest.AppUserID + "@example.com"}, Bot: true},
	}
	if len(got.Labels) != len(want) {
		t.Fatalf("labels = %+v, want %+v", got.Labels, want)
	}
	for i, l := range got.Labels {
		if l.Name != want[i].Name || !slices.Equal(l.By, want[i].By) || l.Bot != want[i].Bot {
			t.Errorf("label %d = %+v, want %+v", i, l, want[i])
		}
	}
	// The open issues that block this one: not the completed one, and not
	// a relation of another kind.
	if want := []string{"ENG-2", "ELSE-9"}; !slices.Equal(got.BlockedBy, want) {
		t.Errorf("blocked by %v, want %v", got.BlockedBy, want)
	}

	// An issue with nothing of all this, and one that Linear does not have.
	if got, err := c.Scheduling(ctx, "ENG-4"); err != nil || got.Priority != 0 || len(got.Labels) != 0 || len(got.BlockedBy) != 0 {
		t.Errorf("Scheduling(ENG-4) = %+v, %v", got, err)
	}
	if _, err := c.Scheduling(ctx, "ENG-404"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("Scheduling of an unknown issue: %v, want ErrNotFound", err)
	}
	api.Fail(true)
	if _, err := c.Scheduling(ctx, "ENG-1"); err == nil || errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("Scheduling with a failing API: %v", err)
	}
	api.Fail(false)

	// The list of the agent's issues has the priority of each.
	list, err := c.Assigned(ctx)
	if err != nil || len(list) != 2 || list[0].Priority != 2 || list[1].Priority != 1 {
		t.Errorf("Assigned = %+v, %v", list, err)
	}

	// Linear counts from 1 (urgent) to 4 (low); anything else is no rank.
	for in, want := range map[float64]int{0: 0, 1: 1, 4: 4, 5: 0, -1: 0} {
		if got := linear.Rank(in); got != want {
			t.Errorf("Rank(%v) = %d, want %d", in, got, want)
		}
	}
}

// What the ticket tools read and write: the issue as a person sees it,
// with its newest comments, oldest first, and a comment as the app.
func TestTicketAndComment(t *testing.T) {
	c, api := client(t)
	api.Add(lineartest.Issue{Key: "ENG-1", Title: "Add a retry", Description: "Retry the payment call.", State: "In Progress", Labels: []string{"backend"}})
	ctx := context.Background()
	got, err := c.Ticket(ctx, "ENG-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != "ENG-1" || got.Title != "Add a retry" || got.Description != "Retry the payment call." || got.Status != "In Progress" ||
		got.URL != "https://linear.app/example/issue/ENG-1" || !slices.Equal(got.Labels, []string{"backend"}) || len(got.Comments) != 0 || got.MoreComments != 0 {
		t.Errorf("ticket = %+v", got)
	}

	api.Say("ENG-1", "u-anna", "the first")
	for range tracker.MaxComments - 1 {
		api.Say("ENG-1", "u-anna", "one more")
	}
	if err := c.Comment(ctx, "ENG-1", "from the agent"); err != nil {
		t.Fatal(err)
	}
	if all := api.Comments("ENG-1"); all[len(all)-1] != (lineartest.Comment{Key: "ENG-1", Body: "from the agent", Author: lineartest.AppUserID}) {
		t.Errorf("the comment on the issue = %+v", all[len(all)-1])
	}
	got, err = c.Ticket(ctx, "ENG-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Comments) != tracker.MaxComments || got.MoreComments == 0 {
		t.Fatalf("%d comments and %d more, want %d and more", len(got.Comments), got.MoreComments, tracker.MaxComments)
	}
	first, last := got.Comments[0], got.Comments[len(got.Comments)-1]
	if first.Body != "one more" || first.Author != "Name of u-anna" || first.Bot || !first.At.Before(last.At) {
		t.Errorf("the oldest comment of the page = %+v", first)
	}
	if last.Body != "from the agent" || !last.Bot {
		t.Errorf("the newest comment = %+v, want the agent's", last)
	}

	if _, err := c.Ticket(ctx, "ENG-404"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("an issue that is not there: %v", err)
	}
	if err := c.Comment(ctx, "ENG-404", "hello"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("a comment on an issue that is not there: %v", err)
	}
}
