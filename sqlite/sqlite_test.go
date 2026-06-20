package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMigrations = [][]string{
	{
		`CREATE TABLE IF NOT EXISTS items (
			id    INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL
		)`,
	},
	{
		`ALTER TABLE items ADD COLUMN done INTEGER NOT NULL DEFAULT 0`,
	},
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	require.NoError(t, db.QueryRow("PRAGMA user_version").Scan(&v))
	return v
}

func TestOpenAppliesMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(path, 0, testMigrations)
	require.NoError(t, err, "Open")
	defer db.Close()

	assert.Equal(t, len(testMigrations), userVersion(t, db), "user_version after Open")

	// The v2 column must exist.
	_, err = db.Exec("INSERT INTO items (title, done) VALUES (?, ?)", "hello", 1)
	assert.NoError(t, err, "insert using migrated schema")

	// WAL mode is set on first migration.
	var mode string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "wal", mode)

	// foreign_keys pragma is on.
	var fk int
	require.NoError(t, db.QueryRow("PRAGMA foreign_keys").Scan(&fk))
	assert.Equal(t, 1, fk)
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(path, 0, testMigrations)
	require.NoError(t, err, "Open")
	defer db.Close()

	// Running again must be a no-op and not error.
	require.NoError(t, Migrate(db, testMigrations), "second Migrate")
	assert.Equal(t, len(testMigrations), userVersion(t, db))
}

func TestMigrateAppliesNewVersionsIncrementally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	// Open with only the first migration.
	db, err := Open(path, 0, testMigrations[:1])
	require.NoError(t, err, "Open with v1 only")
	assert.Equal(t, 1, userVersion(t, db))
	require.NoError(t, db.Close())

	// Reopen with both migrations; only v2 should be applied.
	db, err = Open(path, 0, testMigrations)
	require.NoError(t, err, "Open with v1+v2")
	defer db.Close()
	assert.Equal(t, 2, userVersion(t, db))

	_, err = db.Exec("INSERT INTO items (title, done) VALUES (?, ?)", "hi", 0)
	assert.NoError(t, err, "insert using v2 column after incremental migrate")
}

func TestMigrateFailureLeavesPreviousVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	bad := [][]string{
		testMigrations[0],
		{`THIS IS NOT VALID SQL`},
	}

	db, err := Open(path, 0, bad)
	require.Error(t, err, "Open should fail on bad migration")
	if db != nil {
		db.Close()
	}

	// Reopen to inspect the persisted state: v1 committed, v2 not.
	db, err = Open(path, 0, testMigrations[:1])
	require.NoError(t, err)
	defer db.Close()
	assert.Equal(t, 1, userVersion(t, db), "failed v2 must not advance user_version")
}

func TestOpenWithExtraPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(path, 5000, testMigrations, "synchronous=NORMAL")
	require.NoError(t, err, "Open with extra pragmas")
	defer db.Close()

	var sync int
	require.NoError(t, db.QueryRow("PRAGMA synchronous").Scan(&sync))
	assert.Equal(t, 1, sync, "synchronous=NORMAL maps to 1")
}

func TestCreateDataDir(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "dir", "test.db")
	require.NoError(t, CreateDataDir(dbPath))

	db, err := Open(dbPath, 0, testMigrations)
	require.NoError(t, err, "Open in created directory")
	defer db.Close()
}
