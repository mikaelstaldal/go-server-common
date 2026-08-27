package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlitedrv "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// How long setWALMode keeps retrying another connection's write lock, and how it
// backs off while waiting.
//
// The budget is a fixed wall-clock one rather than the caller's busy_timeout:
// Migrate is not given a busy timeout and cannot be, since that would change its
// signature. Ten seconds is generous for the work being waited on -- setting the
// journal mode of a database that is being created takes milliseconds -- and it
// only ever elapses for a caller that would previously have failed outright.
//
// It bounds the retrying, not the wall clock, and the difference is worth being
// exact about. A single attempt can still sit in SQLite's own busy handler for
// up to the connection's busy_timeout: when the contention is over the shared
// lock rather than over the journal mode, the pragma waits rather than returning
// SQLITE_BUSY. Measured against a peer holding BEGIN EXCLUSIVE, neither this
// budget nor ctx cuts that wait short -- the driver reports a cancelled context
// only once the underlying call has returned. The Exec this replaced blocked in
// exactly the same way, so that is existing behaviour rather than something the
// retry loop introduced.
const (
	walBusyBudget        = 10 * time.Second
	walInitialRetryDelay = 1 * time.Millisecond
	walMaxRetryDelay     = 50 * time.Millisecond
)

// setWALMode puts db into WAL journal mode, retrying while another connection
// holds the write lock.
//
// Journal mode is a property of the file rather than of a transaction and so
// cannot be set inside one. That leaves the pragma exposed to concurrent
// writers, and when the lock it wants is already held SQLite refuses it with
// SQLITE_BUSY *without* consulting the busy handler -- so the busy_timeout a
// caller configures does not bound it and does not help. Two processes creating
// the same database file at the same instant would otherwise leave one of them
// dead on arrival. Retrying here is what gives that wait somewhere to happen.
func setWALMode(ctx context.Context, db *sql.DB) error {
	deadline := time.Now().Add(walBusyBudget)
	delay := walInitialRetryDelay

	for {
		err := setJournalModeWAL(ctx, db)
		if err == nil {
			return nil
		}
		if !isBusy(err) || time.Now().After(deadline) {
			return fmt.Errorf("set WAL mode: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("set WAL mode: %w", ctx.Err())
		case <-time.After(delay):
		}
		delay *= 2
		if delay > walMaxRetryDelay {
			delay = walMaxRetryDelay
		}
	}
}

// setJournalModeWAL runs the pragma and accepts whatever journal mode it reports.
//
// The statement answers with the mode the database ended up in. Any answer is
// accepted, deliberately: a database that cannot be WAL says so by reporting the
// mode it kept rather than by failing, and an in-memory database always answers
// "memory". Callers migrate in-memory databases in their own tests, so a mode
// other than "wal" must not become an error. The row is read rather than
// discarded so that a refusal is distinguishable from a lock, and a pragma that
// reports no row at all is treated as success, exactly as the Exec this replaced
// would have.
func setJournalModeWAL(ctx context.Context, db *sql.DB) error {
	var mode string
	err := db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

// isBusy reports whether err is SQLite saying another connection holds the lock.
//
// modernc.org/sqlite carries the result code on its own error type, which is
// what is inspected here rather than the message text. The primary code is the
// low byte of the extended one, so this matches SQLITE_BUSY_SNAPSHOT and friends
// as well as the bare codes.
func isBusy(err error) bool {
	var sqliteErr *sqlitedrv.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	switch sqliteErr.Code() & 0xff {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return true
	default:
		return false
	}
}
