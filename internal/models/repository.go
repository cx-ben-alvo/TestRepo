package models

// Repository represents a repository record in the database
type Repository struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	GitURL   string `json:"git_url"`
	RepoType string `json:"repo_type"` // "git" or "fetch"
	Created  string `json:"created"`
}
