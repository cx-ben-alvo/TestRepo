package repository

import (
	"database/sql"

	"github.com/checkmarx/correlation-demo/internal/models"
)

// RepositoryStore handles database operations for repositories
type RepositoryStore struct {
	db *sql.DB
}

// NewRepositoryStore creates a new repository store
func NewRepositoryStore(db *sql.DB) *RepositoryStore {
	return &RepositoryStore{db: db}
}

func (r *RepositoryStore) Create(name, gitURL, repoType string) (int64, error) {
	// Use a parameterized query to prevent SQL injection.
	// User-supplied values are passed as separate arguments, never interpolated
	// into the query string.
	result, err := r.db.Exec(
		"INSERT INTO repos (name, git_url, repo_type) VALUES (?, ?, ?)",
		name, gitURL, repoType,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetByID retrieves a repository by ID
func (r *RepositoryStore) GetByID(id int) (*models.Repository, error) {
	var repo models.Repository
	err := r.db.QueryRow("SELECT id, name, git_url, repo_type FROM repos WHERE id = ?", id).
		Scan(&repo.ID, &repo.Name, &repo.GitURL, &repo.RepoType)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &repo, nil
}

// List retrieves all repositories
func (r *RepositoryStore) List() ([]*models.Repository, error) {
	rows, err := r.db.Query("SELECT id, name, git_url, repo_type, created FROM repos ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*models.Repository
	for rows.Next() {
		var repo models.Repository
		if err := rows.Scan(&repo.ID, &repo.Name, &repo.GitURL, &repo.RepoType, &repo.Created); err != nil {
			return nil, err
		}
		repos = append(repos, &repo)
	}

	return repos, nil
}
