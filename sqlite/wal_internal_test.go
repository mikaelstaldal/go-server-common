package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// holdExclusive holds BEGIN EXCLUSIVE on a fresh rollback-journal database at
// path for d. Unlike BEGIN IMMEDIATE, this blocks readers too, which is what
// puts the journal_mode pragma inside SQLite's busy handler instead of getting
// it an immediate SQLITE_BUSY.
func holdExclusive(t *testing.T, path string, d time.Duration) {
	t.Helper()
	ctx := context.Background()

	holder, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=60000")
	require.NoError(t, err)
	conn, err := holder.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "CREATE TABLE seed (x)")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "BEGIN EXCLUSIVE")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "INSERT INTO seed VALUES (1)")
	require.NoError(t, err)

	done := make(chan struct{})
	released := make(chan struct{})
	go func() {
		defer close(released)
		select {
		case <-time.After(d):
		case <-done: // the test finished with it early
		}
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		_ = conn.Close()
		_ = holder.Close()
	}()
	t.Cleanup(func() {
		close(done)
		<-released
	})
}

func poolBusyTimeout(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	require.NoError(t, db.QueryRow("PRAGMA busy_timeout").Scan(&v))
	return v
}

// The budget is a wall-clock bound, and this is the test that says so.
//
// Under BEGIN EXCLUSIVE the contention is over the shared lock rather than over
// the journal mode, so the pragma waits inside SQLite's own busy handler instead
// of being refused. Left on the caller's connection it would sit there for the
// full busy_timeout -- 60s here -- and neither the budget nor ctx could cut it
// short. Running on a connection with busy_timeout = 0 turns that back into an
// immediate SQLITE_BUSY, so the budget decides when to stop.
func TestSetWALModeBudgetIsAWallClockBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	holdExclusive(t, path, 5*time.Second)

	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=60000")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck

	const budget = 300 * time.Millisecond
	start := time.Now()
	err = setWALModeWithin(context.Background(), db, budget)
	elapsed := time.Since(start)

	require.Error(t, err, "the lock is held for the whole test, so this must give up")
	assert.Contains(t, err.Error(), "set WAL mode")
	assert.Less(t, elapsed, 3*time.Second,
		"must return on its own budget, not when the lock releases or the busy handler expires")
}

// busy_timeout is connection state, and sql.Conn.Close hands the connection back
// to the pool with that state intact. A connection returned at 0 would give
// spurious SQLITE_BUSY to whatever borrowed it next, anywhere in the caller's
// program, so the WAL step has to put it back exactly as it found it.
func TestSetWALModeRestoresBusyTimeout(t *testing.T) {
	for _, contended := range []bool{false, true} {
		name := "uncontended"
		if contended {
			name = "contended"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.db")
			if contended {
				holdExclusive(t, path, 300*time.Millisecond)
			}

			db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
			require.NoError(t, err)
			defer db.Close() //nolint:errcheck
			// Force the pool to hand back the same physical connection, which is
			// what makes a leak observable at all.
			db.SetMaxOpenConns(1)

			require.Equal(t, 5000, poolBusyTimeout(t, db), "precondition")
			require.NoError(t, setWALMode(context.Background(), db))
			assert.Equal(t, 5000, poolBusyTimeout(t, db), "busy_timeout must be restored")
		})
	}
}

// The restore must happen even when the caller's context is already cancelled --
// it deliberately does not run on that context, since a connection has to be put
// back whether or not the caller gave up.
func TestSetWALModeRestoresBusyTimeoutAfterCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	holdExclusive(t, path, 3*time.Second)

	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	require.Error(t, setWALMode(ctx, db))

	assert.Equal(t, 5000, poolBusyTimeout(t, db), "restored even though the caller cancelled")
}

// discardConn is the fallback for a connection that cannot be restored. It is
// the one thing standing between a failed restore and a pool full of
// busy_timeout = 0, so prove it actually keeps the connection out rather than
// trusting that it does.
func TestDiscardConnKeepsConnectionOutOfThePool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)

	conn, err := db.Conn(context.Background())
	require.NoError(t, err)
	_, err = conn.ExecContext(context.Background(), "PRAGMA busy_timeout = 0")
	require.NoError(t, err)

	discardConn(conn)

	assert.Equal(t, 5000, poolBusyTimeout(t, db),
		"a connection that was modified and discarded must not come back out of the pool")
}

// The reported HIGH: a clear that takes effect and *then* reports failure.
//
// modernc's stmt.exec replaces an already-successful result with ctx.Err() when
// the context is cancelled between the step and the return, so "PRAGMA
// busy_timeout = 0 returned an error" does not mean the pragma did not apply.
// Treating it as though it did not, and handing the connection back without
// restoring, put a busy_timeout = 0 connection into the pool. The restore is now
// installed before the clear is attempted, so the ambiguity cannot leak.
func TestRunWithoutBusyTimeoutRestoresWhenClearAppliesThenFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
	require.NoError(t, err)
	defer db.Close()      //nolint:errcheck
	db.SetMaxOpenConns(1) // so a leaked connection is the one we get back

	require.Equal(t, 5000, poolBusyTimeout(t, db), "precondition")

	// Exactly the driver's behaviour: apply the pragma, then report failure.
	clearAppliesThenFails := func(ctx context.Context, conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
			return err
		}
		return context.Canceled
	}

	ran := false
	err = runWithoutBusyTimeoutUsing(context.Background(), db, clearAppliesThenFails,
		func(*sql.Conn) error {
			ran = true
			return nil
		})

	require.Error(t, err, "the clear reported failure, so the operation must fail")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, ran, "the body must not run when the clear failed")
	assert.Equal(t, 5000, poolBusyTimeout(t, db),
		"the connection must not go back to the pool with the busy handler off")
}

// And the same for a clear that genuinely did not take effect: restoring
// unconditionally must be harmless, not a source of its own errors.
func TestRunWithoutBusyTimeoutToleratesClearThatNeverApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)

	clearNeverApplies := func(context.Context, *sql.Conn) error { return context.Canceled }

	err = runWithoutBusyTimeoutUsing(context.Background(), db, clearNeverApplies,
		func(*sql.Conn) error { return nil })

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 5000, poolBusyTimeout(t, db), "restore of an unchanged value is a no-op")
}

// busySQLiteError returns a genuine *sqlite.Error carrying SQLITE_BUSY, by
// asking for the journal mode while another connection holds the write lock.
func busySQLiteError(t *testing.T) error {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "busy.db")

	holder, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=60000")
	require.NoError(t, err)
	t.Cleanup(func() { _ = holder.Close() })
	hc, err := holder.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = hc.Close() })
	_, err = hc.ExecContext(ctx, "CREATE TABLE seed (x)")
	require.NoError(t, err)
	_, err = hc.ExecContext(ctx, "BEGIN IMMEDIATE")
	require.NoError(t, err)
	_, err = hc.ExecContext(ctx, "INSERT INTO seed VALUES (1)")
	require.NoError(t, err)

	other, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })
	var mode string
	busyErr := other.QueryRow("PRAGMA journal_mode = WAL").Scan(&mode)
	require.Error(t, busyErr, "the write lock is held, so this must be refused")
	require.True(t, isBusy(busyErr), "precondition: a real SQLITE_BUSY")
	return busyErr
}

// The retry loop decides whether to keep going by running errors.As over the
// driver's own error type. Joining must not put that out of reach.
func TestIsBusyReachesTheDriverErrorThroughAJoin(t *testing.T) {
	busyErr := busySQLiteError(t)

	joined := errors.Join(busyErr, errors.New("restore busy_timeout: connection is closed"))
	assert.True(t, isBusy(joined), "errors.As must still find the driver error")

	// And the other way round, since Join order is not something to rely on.
	assert.True(t, isBusy(errors.Join(errors.New("cleanup failed"), busyErr)))

	// A join carrying no SQLite error at all is still not busy.
	assert.False(t, isBusy(errors.Join(errors.New("a"), errors.New("b"))))
}

// When the operation fails and the restore fails too, both must survive: the
// primary cause stays discoverable with errors.Is, and the cleanup failure --
// which destroyed the connection, and with it a private in-memory database --
// becomes visible instead of being dropped.
func TestRunWithoutBusyTimeoutJoinsRestoreFailureWithThePrimaryError(t *testing.T) {
	for _, primary := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(primary.Error(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.db")
			db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
			require.NoError(t, err)
			defer db.Close() //nolint:errcheck

			err = runWithoutBusyTimeoutUsing(context.Background(), db, clearBusyTimeout,
				func(conn *sql.Conn) error {
					// Break the connection so the restore afterwards cannot succeed.
					_ = conn.Raw(func(any) error { return driver.ErrBadConn })
					return primary
				})

			require.Error(t, err)
			assert.ErrorIs(t, err, primary,
				"MigrateStrict's cancellation contract depends on this surviving the join")
			assert.Contains(t, err.Error(), "busy_timeout",
				"the cleanup failure must be visible, not dropped")
		})
	}
}

// With only one failure there is nothing to join, and the error must come back
// exactly as it is today -- not wrapped in a single-element join, which would
// change its identity for no benefit.
func TestRunWithoutBusyTimeoutDoesNotWrapASingleError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)

	sentinel := errors.New("only the body failed")
	err = runWithoutBusyTimeoutUsing(context.Background(), db, clearBusyTimeout,
		func(*sql.Conn) error { return sentinel })

	assert.Equal(t, sentinel, err, "the single error is returned as-is, identity intact")
	assert.Equal(t, 5000, poolBusyTimeout(t, db), "and the connection still went back clean")
}
