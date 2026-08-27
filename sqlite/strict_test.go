package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mikaelstaldal/go-server-common/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMigrations = [][]string{
	{`CREATE TABLE a (id INTEGER PRIMARY KEY)`, `PRAGMA application_id = 305419896`},
	{`CREATE TABLE b (id INTEGER PRIMARY KEY)`},
}

func openFresh(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout=5000")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func TestMigrateStrictAppliesAllBatches(t *testing.T) {
	db, _ := openFresh(t)
	require.NoError(t, sqlite.MigrateStrict(context.Background(), db, testMigrations))

	version, err := sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 2, version)

	appID, err := sqlite.ApplicationID(db)
	require.NoError(t, err)
	assert.Equal(t, int32(305419896), appID, "application_id set by a migration survives")

	var mode string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "wal", mode)

	for _, table := range []string{"a", "b"} {
		var name string
		require.NoError(t, db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name))
	}
}

func TestMigrateStrictIsIdempotent(t *testing.T) {
	db, _ := openFresh(t)
	require.NoError(t, sqlite.MigrateStrict(context.Background(), db, testMigrations))
	require.NoError(t, sqlite.MigrateStrict(context.Background(), db, testMigrations))

	version, err := sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func TestMigrateStrictResumesAfterPartialMigration(t *testing.T) {
	db, _ := openFresh(t)
	require.NoError(t, sqlite.MigrateStrict(context.Background(), db, testMigrations[:1]))

	version, err := sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 1, version)

	require.NoError(t, sqlite.MigrateStrict(context.Background(), db, testMigrations))
	version, err = sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func TestMigrateStrictRefusesNewerSchema(t *testing.T) {
	db, _ := openFresh(t)
	require.NoError(t, sqlite.MigrateStrict(context.Background(), db, testMigrations))

	err := sqlite.MigrateStrict(context.Background(), db, testMigrations[:1])
	require.Error(t, err)
	assert.ErrorIs(t, err, sqlite.ErrSchemaTooNew)
	assert.Contains(t, err.Error(), "version 2")
}

func TestMigrateStrictLeavesLastCommittedVersionOnFailure(t *testing.T) {
	db, _ := openFresh(t)
	broken := [][]string{testMigrations[0], {`CREATE TABLE b (`}}

	require.Error(t, sqlite.MigrateStrict(context.Background(), db, broken))

	version, err := sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 1, version, "the batch that committed stands, the one that failed does not")
}

// Several processes opening a stale database at once must not apply the same
// batch twice; the write lock is taken before user_version is re-read.
func TestMigrateStrictConcurrent(t *testing.T) {
	_, path := openFresh(t)

	const writers = 4
	var wg sync.WaitGroup
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
			errs[i] = sqlite.MigrateStrict(context.Background(), db, testMigrations)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "writer %d", i)
	}

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	version, err := sqlite.UserVersion(db)
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func TestApplicationIDIsZeroUntilSet(t *testing.T) {
	db, _ := openFresh(t)
	appID, err := sqlite.ApplicationID(db)
	require.NoError(t, err)
	assert.Equal(t, int32(0), appID)
	assert.False(t, errors.Is(err, sqlite.ErrSchemaTooNew))
}
