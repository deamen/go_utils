//go:build unix

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwner refuses a file that belongs to a user other than root or the
// one ochell runs as: an owner can always make a file writable.
func checkOwner(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("policy %s: the file belongs to the user with id %d; it must belong to root or to the user ochell runs as", path, st.Uid)
	}
	return nil
}
