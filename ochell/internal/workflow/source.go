package workflow

import (
	"context"
	"errors"
	"fmt"

	"ochell/internal/github"
)

// ErrElsewhere says that a repository is not on the GitHub that ochell can
// read, so ochell cannot look for its file.
var ErrElsewhere = errors.New("the repository is not on the configured GitHub")

// GitHub reads a repository's WORKFLOW.md through ochell's read-only
// access to GitHub.
//
// It asks GitHub for the file without naming a branch, which GitHub
// answers from the repository's default branch. ochell never looks at a
// working directory or at a ticket's branch for it, both of which the
// agent can write. So what the agent can do to the file is what it can do
// to the default branch, and that is GitHub's to prevent (branch
// protection), as for a merge.
type GitHub struct {
	Client *github.Client
}

// Read returns the content of the file of a repository, named as git
// clone takes it, and the version of that content (the hash that git gives
// it). found is false when the repository has no such file.
//
// It returns ErrElsewhere for a repository on another host. A repository
// that the token cannot see is an error, not a missing file: GitHub
// answers the same for both, and a file that ochell cannot read must not
// count as taken away.
func (g GitHub) Read(ctx context.Context, repo string) (raw []byte, version string, found bool, err error) {
	owner, name, err := github.ParseRepo(repo, g.Client.WebHost())
	if err != nil {
		return nil, "", false, fmt.Errorf("%w: %v", ErrElsewhere, err)
	}
	f, err := g.Client.File(ctx, owner, name, FileName, MaxSize)
	switch {
	case err == nil:
		return f.Content, "sha:" + f.SHA, true, nil
	case !github.NotFound(err):
		return nil, "", false, err
	}
	if err := g.Client.Repository(ctx, owner, name); err != nil {
		if github.NotFound(err) {
			return nil, "", false, fmt.Errorf("github does not show %s/%s to ochell's token (github.token needs read access to the contents of the repository)", owner, name)
		}
		return nil, "", false, err
	}
	return nil, "", false, nil
}
