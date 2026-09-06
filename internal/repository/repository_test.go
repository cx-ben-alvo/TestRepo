package repository

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// newTestDB creates an in-memory SQLite database suitable for testing.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test DB: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE repos (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			name      TEXT NOT NULL,
			git_url   TEXT NOT NULL,
			repo_type TEXT NOT NULL,
			created   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to create test schema: %v", err)
	}
	return db
}

// TestCreate_Functional verifies that valid inputs are stored and retrievable.
func TestCreate_Functional(t *testing.T) {
	db := newTestDB(t)
	defer db.Close()
	store := NewRepositoryStore(db)

	id, err := store.Create("my-repo", "https://github.com/org/my-repo", "git")
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected a positive last-insert ID, got %d", id)
	}

	repo, err := store.GetByID(int(id))
	if err != nil {
		t.Fatalf("GetByID returned unexpected error: %v", err)
	}
	if repo == nil {
		t.Fatal("GetByID returned nil for a row that should exist")
	}
	if repo.Name != "my-repo" {
		t.Errorf("Name: want %q, got %q", "my-repo", repo.Name)
	}
	if repo.GitURL != "https://github.com/org/my-repo" {
		t.Errorf("GitURL: want %q, got %q", "https://github.com/org/my-repo", repo.GitURL)
	}
	if repo.RepoType != "git" {
		t.Errorf("RepoType: want %q, got %q", "git", repo.RepoType)
	}
}

// TestCreate_SQLInjection_Name checks that a SQL-injection payload in the name
// field is stored verbatim and does NOT alter database state.
// Before the fix, the interpolated query could be broken out of its VALUES
// clause, enabling arbitrary SQL execution (e.g. dropping tables).
func TestCreate_SQLInjection_Name(t *testing.T) {
	db := newTestDB(t)
	defer db.Close()
	store := NewRepositoryStore(db)

	// Classic injection payload: terminates the current string literal, then
	// attempts to drop the repos table and starts a dangling comment.
	maliciousName := "'); DROP TABLE repos; --"

	id, err := store.Create(maliciousName, "https://github.com/org/safe", "git")
	if err != nil {
		t.Fatalf("Create returned unexpected error for injection payload: %v", err)
	}

	// The table must still exist — if the injected DROP TABLE had run, List()
	// would fail with "no such table: repos".
	repos, err := store.List()
	if err != nil {
		t.Fatalf("List() failed after injection attempt (table may have been dropped): %v", err)
	}

	// The payload must have been stored as literal data, not executed as SQL.
	var found bool
	for _, r := range repos {
		if r.ID == int(id) && r.Name == maliciousName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("injection payload was not stored as literal data (name=%q, id=%d)", maliciousName, id)
	}
}

// TestCreate_SQLInjection_GitURL checks that a SQL-injection payload in the
// git_url field is also treated as data, not SQL.
func TestCreate_SQLInjection_GitURL(t *testing.T) {
	db := newTestDB(t)
	defer db.Close()
	store := NewRepositoryStore(db)

	maliciousURL := "https://github.com/x', 'x', 'x'); INSERT INTO repos (name, git_url, repo_type) VALUES ('injected', 'injected', 'injected'); --"

	id, err := store.Create("safe-name", maliciousURL, "git")
	if err != nil {
		t.Fatalf("Create returned unexpected error for injection payload: %v", err)
	}

	repos, err := store.List()
	if err != nil {
		t.Fatalf("List() failed after injection attempt: %v", err)
	}

	// Only one row should exist (the legitimate insert).  A successful
	// injection would have added a second "injected" row.
	if len(repos) != 1 {
		t.Errorf("expected exactly 1 row in repos, got %d (possible injected rows)", len(repos))
	}

	// Verify the stored URL is the exact (un-executed) payload string.
	if repos[0].ID == int(id) && repos[0].GitURL != maliciousURL {
		t.Errorf("GitURL: want literal payload %q, got %q", maliciousURL, repos[0].GitURL)
	}
}

// TestCreate_SQLInjection_RepoType checks that a SQL-injection payload in the
// repo_type field is treated as data.
func TestCreate_SQLInjection_RepoType(t *testing.T) {
	db := newTestDB(t)
	defer db.Close()
	store := NewRepositoryStore(db)

	maliciousType := "git'); DELETE FROM repos; --"

	id, err := store.Create("safe-name", "https://github.com/org/repo", maliciousType)
	if err != nil {
		t.Fatalf("Create returned unexpected error for injection payload: %v", err)
	}

	repos, err := store.List()
	if err != nil {
		t.Fatalf("List() failed after injection attempt: %v", err)
	}

	// The DELETE should NOT have run; the row must still be present.
	var found bool
	for _, r := range repos {
		if r.ID == int(id) {
			found = true
			if r.RepoType != maliciousType {
				t.Errorf("RepoType: want literal payload %q, got %q", maliciousType, r.RepoType)
			}
			break
		}
	}
	if !found {
		t.Errorf("row %d not found after injection attempt (may have been deleted by injected DELETE)", id)
	}
}

// TestCreate_SpecialCharacters verifies that special characters that could
// confuse string interpolation are stored and retrieved correctly.
func TestCreate_SpecialCharacters(t *testing.T) {
	db := newTestDB(t)
	defer db.Close()
	store := NewRepositoryStore(db)

	cases := []struct {
		name     string
		gitURL   string
		repoType string
	}{
		{
			name:     "repo with 'single quotes' and \"double quotes\"",
			gitURL:   "https://github.com/org/repo?ref=main&foo=bar",
			repoType: "git",
		},
		{
			name:     "repo\nwith\nnewlines",
			gitURL:   "https://github.com/org/newline-repo",
			repoType: "git",
		},
		{
			name:     "unicode: 中文 éàü",
			gitURL:   "https://github.com/org/unicode-repo",
			repoType: "git",
		},
	}

	for _, tc := range cases {
		id, err := store.Create(tc.name, tc.gitURL, tc.repoType)
		if err != nil {
			t.Errorf("Create(%q) returned unexpected error: %v", tc.name, err)
			continue
		}

		repo, err := store.GetByID(int(id))
		if err != nil {
			t.Errorf("GetByID(%d) returned unexpected error: %v", id, err)
			continue
		}
		if repo == nil {
			t.Errorf("GetByID(%d) returned nil", id)
			continue
		}
		if repo.Name != tc.name {
			t.Errorf("Name: want %q, got %q", tc.name, repo.Name)
		}
		if repo.GitURL != tc.gitURL {
			t.Errorf("GitURL: want %q, got %q", tc.gitURL, repo.GitURL)
		}
	}
}

// TestCreate_MultipleRows verifies that successive inserts each receive a
// distinct ID and that List returns them all.
func TestCreate_MultipleRows(t *testing.T) {
	db := newTestDB(t)
	defer db.Close()
	store := NewRepositoryStore(db)

	for i := 0; i < 3; i++ {
		_, err := store.Create(
			"repo",
			"https://github.com/org/repo",
			"git",
		)
		if err != nil {
			t.Fatalf("Create iteration %d failed: %v", i, err)
		}
	}

	repos, err := store.List()
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(repos) != 3 {
		t.Errorf("expected 3 repos, got %d", len(repos))
	}
}

// TestGetByID_NotFound ensures GetByID returns (nil, nil) for a missing row.
func TestGetByID_NotFound(t *testing.T) {
	db := newTestDB(t)
	defer db.Close()
	store := NewRepositoryStore(db)

	repo, err := store.GetByID(99999)
	if err != nil {
		t.Fatalf("GetByID for non-existent ID returned error: %v", err)
	}
	if repo != nil {
		t.Errorf("expected nil repo for non-existent ID, got %+v", repo)
	}
}
