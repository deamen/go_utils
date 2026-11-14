package linear_test

import (
	"context"
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
