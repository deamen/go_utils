package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"ochell/internal/config"
)

// The backup of the store. The store holds what cannot be rebuilt from the
// trackers: the agents' session ids, the messages that wait for a run, and
// the record of every run. ochell writes a consistent copy to backup.dir
// at every backup.interval and keeps the newest backup.keep of them.

// backupPrefix and backupSuffix frame the name of a backup file; the time
// it was made is between them.
const (
	backupPrefix = "ochell-"
	backupSuffix = ".db"
	backupStamp  = "20060102T150405.000Z"
)

// ErrNoBackupDir is returned by Backup when no directory was given and
// none is configured.
var ErrNoBackupDir = errors.New("no backup directory: set backup.dir, or name a file")

// UseBackup sets where and how often the store is backed up. Call it
// before Start. Without it there is no scheduled backup.
func (r *Runner) UseBackup(cfg config.Backup) { r.backup = cfg }

// runBackup makes a backup when the newest one is older than the
// interval, and then at every interval, until Shutdown.
func (r *Runner) runBackup() {
	defer r.wg.Done()
	wait := time.Duration(0)
	if last, ok := r.lastBackup(); ok {
		wait = max(r.backup.Interval-time.Since(last), 0)
	}
	for {
		select {
		case <-r.quit:
			return
		case <-time.After(wait):
		}
		if path, err := r.Backup(""); err != nil {
			r.log.Error("the backup of the store failed", "err", err)
		} else {
			r.log.Info("store backed up", "file", path)
		}
		wait = r.backup.Interval
	}
}

// backups returns the names of the backup files in backup.dir, oldest
// first.
func (r *Runner) backups() []string {
	entries, err := os.ReadDir(r.backup.Dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, backupPrefix) || !strings.HasSuffix(n, backupSuffix) {
			continue
		}
		if _, err := time.Parse(backupStamp, strings.TrimSuffix(strings.TrimPrefix(n, backupPrefix), backupSuffix)); err == nil {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names
}

// lastBackup returns when the newest backup was made.
func (r *Runner) lastBackup() (time.Time, bool) {
	names := r.backups()
	if len(names) == 0 {
		return time.Time{}, false
	}
	n := names[len(names)-1]
	at, err := time.Parse(backupStamp, strings.TrimSuffix(strings.TrimPrefix(n, backupPrefix), backupSuffix))
	return at, err == nil
}

// Backup writes a consistent copy of the store and returns its path. With
// an empty dest the copy goes to backup.dir under a name with the time,
// and the backups beyond backup.keep are removed; otherwise to the file
// dest, which must not exist.
func (r *Runner) Backup(dest string) (string, error) {
	scheduled := dest == ""
	if scheduled {
		if r.backup.Dir == "" {
			return "", ErrNoBackupDir
		}
		// The backups hold what the store holds: for ochell's user only.
		if err := os.MkdirAll(r.backup.Dir, 0o700); err != nil {
			return "", fmt.Errorf("backup directory: %w", err)
		}
		dest = filepath.Join(r.backup.Dir, backupPrefix+time.Now().UTC().Format(backupStamp)+backupSuffix)
	}
	if err := r.store.Backup(dest); err != nil {
		return "", err
	}
	if scheduled && r.backup.Keep > 0 {
		names := r.backups()
		for _, old := range names[:max(len(names)-r.backup.Keep, 0)] {
			if err := os.Remove(filepath.Join(r.backup.Dir, old)); err != nil {
				r.log.Warn("cannot remove an old backup", "file", old, "err", err)
			}
		}
	}
	return dest, nil
}
