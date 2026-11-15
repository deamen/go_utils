//go:build !unix

package policy

import "os"

// checkOwner checks nothing where a file has no owning user id. ochell is
// deployed on Linux; elsewhere it is built for development only.
func checkOwner(string, os.FileInfo) error { return nil }
