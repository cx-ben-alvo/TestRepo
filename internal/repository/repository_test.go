package repository

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// newTestDB opens an in-memory SQLite database and creates the repos table
// with the same schema used in production (see internal/database/database.go).
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory database: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE repos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			git_url TEXT NOT NULL,
			repo_type TEXT NOT NULL,
			created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to create repos table: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestCreate_BasicInsert verifies that Create stores a record and returns a
// positive last-insert ID.
func TestCreate_BasicInsert(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	id, err := store.Create("my-repo", "https://github.com/user/repo", "git")
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected a positive last-insert ID, got %d", id)
	}
}

// TestCreate_FieldsPersistedCorrectly verifies that the values passed to
// Create are stored verbatim in the database row (no truncation, escaping, or
// corruption introduced by the parameterized query path).
func TestCreate_FieldsPersistedCorrectly(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	name := "demo-service"
	gitURL := "https://github.com/org/demo-service"
	repoType := "git"

	id, err := store.Create(name, gitURL, repoType)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}

	var gotName, gotURL, gotType string
	err = db.QueryRow("SELECT name, git_url, repo_type FROM repos WHERE id = ?", id).
		Scan(&gotName, &gotURL, &gotType)
	if err != nil {
		t.Fatalf("QueryRow error: %v", err)
	}

	if gotName != name {
		t.Errorf("name: want %q, got %q", name, gotName)
	}
	if gotURL != gitURL {
		t.Errorf("git_url: want %q, got %q", gitURL, gotURL)
	}
	if gotType != repoType {
		t.Errorf("repo_type: want %q, got %q", repoType, gotType)
	}
}

// TestCreate_SQLInjectionInName verifies that a SQL-injection payload supplied
// as the name parameter is stored as literal text and does NOT alter the
// database structure or corrupt other rows.
//
// Before the fix, the query was built with fmt.Sprintf, so a payload such as
//
//	'); DROP TABLE repos; --
//
// would have been executed as a second statement, dropping the table.
// After the fix, the payload must be stored verbatim in the name column.
func TestCreate_SQLInjectionInName(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	// Classic "drop table" injection in the name field.
	injectedName := "'); DROP TABLE repos; --"

	id, err := store.Create(injectedName, "https://github.com/user/repo", "git")
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	// The repos table must still exist and the row must be readable.
	var gotName string
	err = db.QueryRow("SELECT name FROM repos WHERE id = ?", id).Scan(&gotName)
	if err != nil {
		t.Fatalf("unexpected error reading back row (table may have been dropped): %v", err)
	}
	if gotName != injectedName {
		t.Errorf("name was not stored verbatim: want %q, got %q", injectedName, gotName)
	}
}

// TestCreate_SQLInjectionInGitURL verifies that a SQL-injection payload in the
// git_url parameter is treated as a literal string.
func TestCreate_SQLInjectionInGitURL(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	injectedURL := "https://github.com/x/y' OR '1'='1"

	id, err := store.Create("safe-name", injectedURL, "git")
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	var gotURL string
	err = db.QueryRow("SELECT git_url FROM repos WHERE id = ?", id).Scan(&gotURL)
	if err != nil {
		t.Fatalf("unexpected error reading back row: %v", err)
	}
	if gotURL != injectedURL {
		t.Errorf("git_url was not stored verbatim: want %q, got %q", injectedURL, gotURL)
	}
}

// TestCreate_SQLInjectionInRepoType verifies that a SQL-injection payload in
// the repo_type parameter is treated as a literal string.
func TestCreate_SQLInjectionInRepoType(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	injectedType := "git'; INSERT INTO repos (name, git_url, repo_type) VALUES ('evil','evil','evil'); --"

	id, err := store.Create("safe-name", "https://github.com/user/repo", injectedType)
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	// Only one row must have been inserted (the injected INSERT must not have run).
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM repos").Scan(&count)
	if err != nil {
		t.Fatalf("COUNT query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 row after insertion, got %d (possible injection succeeded)", count)
	}

	// The stored value must be the literal payload, not an altered string.
	var gotType string
	err = db.QueryRow("SELECT repo_type FROM repos WHERE id = ?", id).Scan(&gotType)
	if err != nil {
		t.Fatalf("unexpected error reading back row: %v", err)
	}
	if gotType != injectedType {
		t.Errorf("repo_type was not stored verbatim: want %q, got %q", injectedType, gotType)
	}
}

// TestCreate_SpecialCharactersInFields verifies that legitimate special
// characters (single quotes, double quotes, backslashes, newlines) are stored
// correctly and do not break the query.
func TestCreate_SpecialCharactersInFields(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	cases := []struct {
		name     string
		gitURL   string
		repoType string
	}{
		{
			name:     "O'Brien's project",
			gitURL:   "https://github.com/o-brien/project",
			repoType: "git",
		},
		{
			name:     `back\slash`,
			gitURL:   "https://github.com/user/back-slash",
			repoType: "git",
		},
		{
			name:     "line\nnewline",
			gitURL:   "https://github.com/user/newline",
			repoType: "git",
		},
		{
			name:     `double"quote`,
			gitURL:   "https://github.com/user/doublequote",
			repoType: "git",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := store.Create(tc.name, tc.gitURL, tc.repoType)
			if err != nil {
				t.Fatalf("Create error: %v", err)
			}
			var gotName, gotURL, gotType string
			err = db.QueryRow("SELECT name, git_url, repo_type FROM repos WHERE id = ?", id).
				Scan(&gotName, &gotURL, &gotType)
			if err != nil {
				t.Fatalf("QueryRow error: %v", err)
			}
			if gotName != tc.name {
				t.Errorf("name: want %q, got %q", tc.name, gotName)
			}
			if gotURL != tc.gitURL {
				t.Errorf("git_url: want %q, got %q", tc.gitURL, gotURL)
			}
			if gotType != tc.repoType {
				t.Errorf("repo_type: want %q, got %q", tc.repoType, gotType)
			}
		})
	}
}

// TestCreate_MultipleInserts verifies that consecutive calls to Create each
// produce a distinct, auto-incremented ID.
func TestCreate_MultipleInserts(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	ids := make(map[int64]struct{})
	for i := 0; i < 5; i++ {
		id, err := store.Create(
			"repo-"+strings.Repeat("x", i+1),
			"https://github.com/user/repo",
			"git",
		)
		if err != nil {
			t.Fatalf("Create[%d] error: %v", i, err)
		}
		if _, dup := ids[id]; dup {
			t.Errorf("duplicate last-insert ID %d on iteration %d", id, i)
		}
		ids[id] = struct{}{}
	}
	if len(ids) != 5 {
		t.Errorf("expected 5 distinct IDs, got %d", len(ids))
	}
}

// TestGetByID_ReturnsInsertedRecord verifies that GetByID retrieves the
// correct record after a parameterized Create call.
func TestGetByID_ReturnsInsertedRecord(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	name := "test-repo"
	gitURL := "https://github.com/user/test-repo"
	repoType := "git"

	id, err := store.Create(name, gitURL, repoType)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}

	repo, err := store.GetByID(int(id))
	if err != nil {
		t.Fatalf("GetByID error: %v", err)
	}
	if repo == nil {
		t.Fatal("GetByID returned nil for an existing record")
	}
	if repo.Name != name {
		t.Errorf("Name: want %q, got %q", name, repo.Name)
	}
	if repo.GitURL != gitURL {
		t.Errorf("GitURL: want %q, got %q", gitURL, repo.GitURL)
	}
	if repo.RepoType != repoType {
		t.Errorf("RepoType: want %q, got %q", repoType, repo.RepoType)
	}
}

// TestGetByID_NonExistentRecord verifies that GetByID returns nil (not an
// error) when no matching row exists.
func TestGetByID_NonExistentRecord(t *testing.T) {
	db := newTestDB(t)
	store := NewRepositoryStore(db)

	repo, err := store.GetByID(9999)
	if err != nil {
		t.Fatalf("expected nil error for missing record, got: %v", err)
	}
	if repo != nil {
		t.Errorf("expected nil repo for missing record, got %+v", repo)
	}
}
