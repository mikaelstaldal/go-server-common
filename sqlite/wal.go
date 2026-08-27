package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
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
// It is a true wall-clock bound, which it only is because the retry runs on a
// connection whose own busy handler has been turned off; see
// runWithoutBusyTimeout for why that is required.
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
	return setWALModeWithin(ctx, db, walBusyBudget)
}

// setWALModeWithin is setWALMode with the budget supplied, so that tests can
// assert the bound holds without waiting out the real one.
func setWALModeWithin(ctx context.Context, db *sql.DB, budget time.Duration) error {
	return runWithoutBusyTimeout(ctx, db, func(conn *sql.Conn) error {
		deadline := time.Now().Add(budget)
		delay := walInitialRetryDelay

		for {
			err := setJournalModeWAL(ctx, conn)
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
	})
}

// runWithoutBusyTimeout borrows a connection, turns off its busy handler for the
// duration of f, and puts it back as it was found.
//
// The retry loop needs every attempt to fail fast. Which lock is contended
// decides whether it does: contention over the journal mode itself is refused
// with an immediate SQLITE_BUSY, but contention over the shared lock puts the
// pragma inside SQLite's own busy handler, where it waits for up to the
// connection's busy_timeout and neither the budget nor ctx can reach it. Setting
// busy_timeout = 0 turns that wait back into an immediate SQLITE_BUSY, which is
// what makes the budget a real bound rather than an aspiration.
//
// busy_timeout is connection state, and sql.Conn.Close returns the connection to
// the pool with that state intact. A connection handed back at 0 would give
// spurious SQLITE_BUSY to whatever borrowed it next, anywhere in the caller's
// program and far from here -- including MigrateStrict's own BEGIN IMMEDIATE,
// which depends on the caller's busy_timeout to bound its wait for the migration
// lock. So the original is read first, restored afterwards, and the restore is
// verified; a connection that cannot be put back exactly as it was found is
// destroyed rather than returned to the pool.
func runWithoutBusyTimeout(ctx context.Context, db *sql.DB, f func(*sql.Conn) error) error {
	return runWithoutBusyTimeoutUsing(ctx, db, clearBusyTimeout, f)
}

// clearBusyTimeout turns the connection's busy handler off.
func clearBusyTimeout(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 0")
	return err
}

// runWithoutBusyTimeoutUsing is runWithoutBusyTimeout with the clearing step
// supplied, so that tests can drive the case where it reports failure after
// having taken effect.
func runWithoutBusyTimeoutUsing(
	ctx context.Context,
	db *sql.DB,
	clear func(context.Context, *sql.Conn) error,
	f func(*sql.Conn) error,
) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}

	// Reading changes nothing, so a failure here can hand the connection straight
	// back untouched.
	var original int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&original); err != nil {
		conn.Close() //nolint:errcheck // nothing has been changed on it
		return fmt.Errorf("read busy_timeout: %w", err)
	}

	// Installed before the clear is attempted rather than after it succeeds,
	// because the result of an attempted mutation is ambiguous: an error does not
	// mean it did not happen. This driver's exec replaces an already-successful
	// result with ctx.Err() when the context is cancelled between the step and
	// the return, so a cancelled clear can leave busy_timeout at 0 and still
	// report failure. Restoring unconditionally makes that ambiguity harmless --
	// if the clear never took, the restore writes back the value already there.
	defer func() {
		if restoreErr := restoreBusyTimeout(conn, original); restoreErr != nil {
			discardConn(conn)
			// Both are worth keeping when both happen: the primary error says why
			// the operation failed, the restore error says that cleanup destroyed
			// the connection -- which for a private in-memory database means the
			// caller's schema went with it. Joining keeps errors.Is and errors.As
			// working on the primary cause while making that visible.
			if err == nil {
				err = restoreErr
			} else {
				err = errors.Join(err, restoreErr)
			}
			return
		}
		conn.Close() //nolint:errcheck // the connection is being returned to the pool
	}()

	if clearErr := clear(ctx, conn); clearErr != nil {
		return fmt.Errorf("clear busy_timeout: %w", clearErr)
	}

	return f(conn)
}

// restoreBusyTimeout puts busy_timeout back and confirms it took.
func restoreBusyTimeout(conn *sql.Conn, original int) error {
	// Deliberately not the caller's context: the connection has to be put back as
	// it was found even when the caller has cancelled, and a connection-local
	// pragma takes no locks and cannot block.
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", original)); err != nil {
		return fmt.Errorf("restore busy_timeout: %w", err)
	}
	var got int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&got); err != nil {
		return fmt.Errorf("verify busy_timeout: %w", err)
	}
	if got != original {
		return fmt.Errorf("restore busy_timeout: reads %d, expected %d", got, original)
	}
	return nil
}

// discardConn destroys a connection instead of returning it to the pool, for
// when it cannot be handed back in the state it was borrowed in. Reporting
// driver.ErrBadConn from a Raw callback is what tells database/sql not to reuse
// it; that also releases the connection, so no Close is needed afterwards.
func discardConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
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
func setJournalModeWAL(ctx context.Context, conn *sql.Conn) error {
	var mode string
	err := conn.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode)
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
