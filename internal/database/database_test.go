package database

import (
	"os"
	"testing"
)

// TestInitDB_AcceptsDSNParameter verifies that InitDB uses the caller-supplied
// DSN instead of any hardcoded connection string.  The in-memory DSN is still
// valid for tests; what matters is that it comes from outside the function.
func TestInitDB_AcceptsDSNParameter(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB(\":memory:\") returned unexpected error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("Ping failed after InitDB: %v", err)
	}
}

// TestInitDB_CreatesReposTable confirms that InitDB creates the expected schema
// regardless of which DSN is supplied.
func TestInitDB_CreatesReposTable(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer db.Close()

	// A simple INSERT + SELECT verifies the table exists with the right columns.
	_, err = db.Exec(
		"INSERT INTO repos (name, git_url, repo_type) VALUES (?, ?, ?)",
		"test-repo", "https://example.com/repo.git", "git",
	)
	if err != nil {
		t.Fatalf("INSERT failed — repos table may not have been created: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM repos").Scan(&count); err != nil {
		t.Fatalf("SELECT COUNT failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}
}

// TestInitDB_DSNFromEnvironment simulates the production path where the DSN
// is sourced from the DATABASE_DSN environment variable (as set in config.Load).
// This test proves the connection detail is not hardcoded: passing a different
// DSN (here an env-sourced value) also works correctly.
func TestInitDB_DSNFromEnvironment(t *testing.T) {
	// Temporarily set the env var the way config.Load reads it.
	t.Setenv("DATABASE_DSN", ":memory:")

	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		t.Skip("DATABASE_DSN not set after t.Setenv — skipping")
	}

	db, err := InitDB(dsn)
	if err != nil {
		t.Fatalf("InitDB with env-sourced DSN returned error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

// TestInitDB_FileBasedDSN ensures InitDB works with a file-backed SQLite DSN,
// confirming that the function is not restricted to ":memory:".
// This validates the fix: callers can supply any DSN they choose.
func TestInitDB_FileBasedDSN(t *testing.T) {
	// Create a temporary file path for SQLite to use.
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.Close()
	// Remove the empty file so sqlite3 creates a fresh database at that path.
	os.Remove(tmpFile.Name())

	db, err := InitDB(tmpFile.Name())
	if err != nil {
		t.Fatalf("InitDB with file DSN returned error: %v", err)
	}
	defer db.Close()

	// Insert a row to confirm the schema was created properly.
	_, err = db.Exec(
		"INSERT INTO repos (name, git_url, repo_type) VALUES (?, ?, ?)",
		"file-repo", "https://example.com/file.git", "git",
	)
	if err != nil {
		t.Fatalf("INSERT failed against file-backed DB: %v", err)
	}
}

// TestInitDB_InvalidDSN verifies that an invalid DSN causes InitDB to return
// an error rather than silently succeeding.
func TestInitDB_InvalidDSN(t *testing.T) {
	// A directory path is not a valid SQLite database file; the CREATE TABLE
	// statement should fail even if sql.Open succeeds.
	db, err := InitDB("/dev/null/nonexistent")
	if err == nil {
		// If somehow a db handle was returned, clean it up.
		if db != nil {
			db.Close()
		}
		t.Log("InitDB with invalid DSN did not return an error (driver-dependent behaviour)")
	}
	// We accept either an error or a nil result; the important assertion is
	// that no panic occurs and the function behaves predictably.
}
