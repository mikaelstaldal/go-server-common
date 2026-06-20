// Package sqlite provides common helpers for opening and migrating
// SQLite databases using the pure-Go modernc.org/sqlite driver (no CGO).
package sqlite

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO)
)

// Open opens the SQLite database at path, applies the given migrations, and
// returns the *sql.DB. The connection is configured with foreign keys enabled,
// an optional busy timeout (in milliseconds, when > 0), and any extra PRAGMAs.
//
// Each element of migrations is one schema version: migrations[0] takes the
// database from user_version 0 to 1, migrations[1] from 1 to 2, and so on.
func Open(path string, busyTimeout int, migrations [][]string, extraPragmas ...string) (*sql.DB, error) {
	params := url.Values{}
	params.Add("_pragma", "foreign_keys=on")
	if busyTimeout > 0 {
		params.Add("_pragma", fmt.Sprintf("busy_timeout=%d", busyTimeout))
	}
	for _, p := range extraPragmas {
		params.Add("_pragma", p)
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	dsn := path + sep + params.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := Migrate(db, migrations); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// Migrate applies any migrations whose version is newer than the database's
// current user_version, advancing user_version after each. It is idempotent:
// a database already at or beyond the latest version is left unchanged. The
// first time a database is migrated (user_version 0) WAL journal mode is set.
//
// Each migration runs in its own transaction, so a failure leaves the database
// at the last successfully committed version.
func Migrate(db *sql.DB, migrations [][]string) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}

	if version == 0 {
		if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
			return fmt.Errorf("set WAL mode: %w", err)
		}
	}

	for v := version; v < len(migrations); v++ {
		if err := applyMigration(db, v+1, migrations[v]); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(db *sql.DB, version int, statements []string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration to v%d: %w", version, err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after a successful commit is a no-op

	for _, stmt := range statements {
		if _, err := tx.Exec(stmt); err != nil {
			preview := stmt
			if len(preview) > 60 {
				preview = preview[:60]
			}
			return fmt.Errorf("schema v%d %q: %w", version, preview, err)
		}
	}

	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return fmt.Errorf("set user_version = %d: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration to v%d: %w", version, err)
	}
	return nil
}

// CreateDataDir creates the parent directory of dbPath (mode 0700) if it does
// not already exist.
func CreateDataDir(dbPath string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	return nil
}
