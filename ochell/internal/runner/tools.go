package runner

import (
	"errors"
	"fmt"
	"strings"

	"ochell/internal/mcp"
	"ochell/internal/task"
)

// The ticket tools are ochell's own MCP server (package mcp). A run whose
// tier grants them gets the address of the server and a token that is made
// for that run and opens that run's ticket only. The token is a secret of
// the run, like a minted credential: it is redacted, it does not pass
// through the unit's settings, and it opens nothing once the run has ended.

// UseTicketTools turns the ticket tools on: srv serves them, url is its
// address for an agent on this host, and ownSecrets is what ochell itself
// reaches the trackers with, which a run with the tools must not hold.
// Call it before UsePolicy.
func (r *Runner) UseTicketTools(srv *mcp.Server, url string, ownSecrets []string) {
	r.tools, r.toolsURL = srv, url
	for _, s := range ownSecrets {
		if len(s) >= minSecret {
			r.ownSecrets = append(r.ownSecrets, s)
		}
	}
}

// grantTools adds the ticket tools to what a run gets. It refuses when the
// run would also hold one of ochell's own tracker secrets: the tools are
// there so that no tracker token reaches the agent.
func (r *Runner) grantTools(t *task.Task, g *granted) error {
	if r.tools == nil {
		return errors.New("the host has them turned off (ticket_tools.enabled)")
	}
	for _, list := range [][]string{g.env, g.secrets, r.taskEnv(t), r.inheritedEnv()} {
		for _, e := range list {
			name, value, _ := strings.Cut(e, "=")
			for _, own := range r.ownSecrets {
				if strings.Contains(value, own) {
					return fmt.Errorf("%s in the run's environment holds a secret with which ochell itself reaches a tracker; a run with the ticket tools must not get one", name)
				}
			}
		}
	}
	token, err := mcp.NewToken()
	if err != nil {
		return err
	}
	g.toolsToken = token
	g.env = append(g.env, mcp.EnvURL+"="+r.toolsURL)
	// First, so that the minted credentials stay at the end (describe).
	g.secrets = append([]string{mcp.EnvToken + "=" + token}, g.secrets...)
	return nil
}
