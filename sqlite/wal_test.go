package sqlite_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikaelstaldal/go-server-common/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// holdWriteLock takes the database's write lock on a connection of its own and
// holds it for d. PRAGMA journal_mode is refused with SQLITE_BUSY while that
// lock is held, and refused without the busy handler being consulted, so this is
// what turns the WAL race from something that happens about one run in eight
// into something that happens every run.
func holdWriteLock(t *testing.T, path string, d time.Duration) {
	t.Helper()
	ctx := context.Background()

	holder, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=10000")
	require.NoError(t, err)
	conn, err := holder.Conn(ctx)
	require.NoError(t, err)
	// BEGIN IMMEDIATE takes the write lock now rather than on the first write.
	_, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE")
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

func journalModeOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	var mode string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode").Scan(&mode))
	return mode
}

// Migrate must wait the write lock out rather than dying on arrival, which is
// what it did while the pragma's SQLITE_BUSY went unhandled.
func TestMigrateWaitsOutWriteLockForWAL(t *testing.T) {
	db, path := openFresh(t)
	holdWriteLock(t, path, 250*time.Millisecond)

	start := time.Now()
	require.NoError(t, sqlite.Migrate(db, testMigrations), "Migrate while another connection holds the write lock")
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond, "Migrate should have waited for the lock, not raced past it")

	assert.Equal(t, "wal", journalModeOf(t, db))
	version, err := sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, len(testMigrations), version)
}

// The same for the strict path, whose BEGIN IMMEDIATE re-read protects the
// batches but runs after this pragma and so never covered it.
func TestMigrateStrictWaitsOutWriteLockForWAL(t *testing.T) {
	db, path := openFresh(t)
	holdWriteLock(t, path, 250*time.Millisecond)

	start := time.Now()
	require.NoError(t, sqlite.MigrateStrict(context.Background(), db, testMigrations),
		"MigrateStrict while another connection holds the write lock")
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond, "MigrateStrict should have waited for the lock")

	assert.Equal(t, "wal", journalModeOf(t, db))
	version, err := sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, len(testMigrations), version)
}

// A database that is already WAL answers the pragma without needing the write
// lock, so a second process starting up against one is never held up by it.
// (This passed before the retry loop existed too; it is here to keep it true.)
func TestMigrateOnExistingWALDatabaseIgnoresWriteLock(t *testing.T) {
	db, path := openFresh(t)

	other, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })
	var mode string
	require.NoError(t, other.QueryRow("PRAGMA journal_mode = WAL").Scan(&mode))
	require.Equal(t, "wal", mode)

	// Held for far longer than waiting it out would be acceptable.
	holdWriteLock(t, path, 2*time.Second)

	start := time.Now()
	require.NoError(t, sqlite.Migrate(db, nil), "WAL is already set, so there is nothing to wait for")
	assert.Less(t, time.Since(start), time.Second, "should not wait for a lock it does not need")
}

// The wait has to respect ctx rather than sit out the whole retry budget.
func TestMigrateStrictWALWaitRespectsContext(t *testing.T) {
	db, path := openFresh(t)
	holdWriteLock(t, path, 3*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := sqlite.MigrateStrict(ctx, db, testMigrations)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second, "must give up with ctx, not burn the whole budget")
}

// Several processes creating the same database file at the same instant race on
// the journal_mode pragma alone; no migrations are needed to provoke it.
func TestMigrateConcurrentFirstStartupSetsWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	const writers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=10000")
			if err != nil {
				errs[i] = err
				return
			}
			defer db.Close() //nolint:errcheck
			<-start
			errs[i] = sqlite.Migrate(db, nil)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "writer %d", i)
	}

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	assert.Equal(t, "wal", journalModeOf(t, db))
}

// An in-memory database cannot be WAL: the pragma answers "memory",
// successfully and with no error. Callers run their repository tests against
// in-memory databases, so that has to stay a success rather than become a
// failure now that the pragma's answer is read rather than discarded.
func TestMigrateInMemoryDatabaseIsNotWAL(t *testing.T) {
	migrators := map[string]func(*sql.DB) error{
		"Migrate": func(db *sql.DB) error { return sqlite.Migrate(db, testMigrations) },
		"MigrateStrict": func(db *sql.DB) error {
			return sqlite.MigrateStrict(context.Background(), db, testMigrations)
		},
	}
	// The plain form gives every connection a database of its own; the shared
	// form is what a test suite that wants several connections uses. Both answer
	// "memory".
	dsns := map[string]string{
		"private": ":memory:",
		"shared":  "file:%s?mode=memory&cache=shared",
	}
	for name, migrate := range migrators {
		for kind, dsn := range dsns {
			t.Run(name+"/"+kind, func(t *testing.T) {
				if strings.Contains(dsn, "%s") {
					dsn = fmt.Sprintf(dsn, name)
				}
				db, err := sql.Open("sqlite", dsn)
				require.NoError(t, err)
				defer db.Close() //nolint:errcheck
				// A private in-memory database lives on one connection only.
				db.SetMaxOpenConns(1)

				require.NoError(t, migrate(db))

				assert.Equal(t, "memory", journalModeOf(t, db))
				version, err := sqlite.UserVersion(db)
				require.NoError(t, err)
				assert.Equal(t, len(testMigrations), version)
			})
		}
	}
}
