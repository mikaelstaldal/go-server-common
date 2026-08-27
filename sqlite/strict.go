package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrSchemaTooNew is returned by MigrateStrict when the database's user_version
// is higher than the number of migrations the caller carries, meaning the file
// was written by a newer build than this one.
var ErrSchemaTooNew = errors.New("database schema is newer than this binary understands")

// UserVersion returns SQLite's user_version for db, which Migrate and
// MigrateStrict use as the schema version.
func UserVersion(db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("read user_version: %w", err)
	}
	return version, nil
}

// ApplicationID returns SQLite's application_id for db. It is zero unless
// something has set it, which makes it a convenient stamp identifying the
// application a database file belongs to.
func ApplicationID(db *sql.DB) (int32, error) {
	var id int32
	if err := db.QueryRow("PRAGMA application_id").Scan(&id); err != nil {
		return 0, fmt.Errorf("read application_id: %w", err)
	}
	return id, nil
}

// MigrateStrict is Migrate with two additional guarantees, for databases that
// several processes may open at the same moment.
//
// Each migration runs inside a BEGIN IMMEDIATE transaction that re-reads
// user_version after taking the write lock, so two processes opening a stale
// database concurrently cannot both decide a batch still needs applying. As in
// Migrate, migrations[0] takes the database from user_version 0 to 1, each runs
// in its own transaction, and a failure leaves the database at the last version
// that committed.
//
// A database whose user_version exceeds len(migrations) is refused with
// ErrSchemaTooNew rather than operated on, since this build does not know the
// schema it would be writing to.
func MigrateStrict(ctx context.Context, db *sql.DB, migrations [][]string) error {
	version, err := UserVersion(db)
	if err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("%w: database is at schema version %d, this binary knows %d",
			ErrSchemaTooNew, version, len(migrations))
	}
	if version == len(migrations) {
		return nil
	}

	// journal_mode is a property of the file rather than of a transaction and
	// cannot be set inside one, so it is set once before any batch runs.
	if version == 0 {
		if err := setWALMode(ctx, db); err != nil {
			return err
		}
	}

	for {
		applied, err := applyNextStrict(ctx, db, migrations)
		if err != nil {
			return err
		}
		if !applied {
			return nil
		}
	}
}

// applyNextStrict applies whichever migration the database needs next, deciding
// which one that is only after the write lock is held. It reports whether it
// applied one.
func applyNextStrict(ctx context.Context, db *sql.DB, migrations [][]string) (bool, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Close() //nolint:errcheck // the connection is being returned to the pool

	// BEGIN IMMEDIATE takes the write lock now rather than on the first write,
	// so the user_version read below cannot be overtaken by another process.
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return false, fmt.Errorf("begin migration transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	var version int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return false, fmt.Errorf("read user_version: %w", err)
	}
	if version > len(migrations) {
		return false, fmt.Errorf("%w: database is at schema version %d, this binary knows %d",
			ErrSchemaTooNew, version, len(migrations))
	}
	if version == len(migrations) {
		return false, nil
	}

	next := version + 1
	for _, stmt := range migrations[version] {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return false, fmt.Errorf("schema v%d %q: %w", next, preview(stmt), err)
		}
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", next)); err != nil {
		return false, fmt.Errorf("set user_version = %d: %w", next, err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return false, fmt.Errorf("commit migration to v%d: %w", next, err)
	}
	committed = true
	return true, nil
}

func preview(stmt string) string {
	if len(stmt) > 60 {
		return stmt[:60]
	}
	return stmt
}
