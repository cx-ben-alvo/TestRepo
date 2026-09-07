package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/checkmarx/correlation-demo/internal/models"
	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// ContentSecurityPolicy is the CSP header value applied to all responses.
// It restricts content sources to the same origin, mitigating XSS and
// content-injection attacks (CWE-346).
const ContentSecurityPolicy = "default-src 'self'"

// WithCSP wraps an http.HandlerFunc to set a strict Content-Security-Policy
// header on every response before the handler writes any content.
func WithCSP(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		fn(w, r)
	}
}

type Handler struct {
	repoStore  *repository.RepositoryStore
	validator  *service.DomainValidator
	gitService *service.GitService
}

func NewHandler(
	repoStore *repository.RepositoryStore,
	validator *service.DomainValidator,
	gitService *service.GitService,
) *Handler {
	return &Handler{
		repoStore:  repoStore,
		validator:  validator,
		gitService: gitService,
	}
}

func (h *Handler) CreateRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.FormValue("name")
	gitURL := r.FormValue("git_url")
	repoType := r.FormValue("repo_type")

	if name == "" || gitURL == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if repoType == "" {
		repoType = "git"
	}

	if !h.validator.IsWhitelisted(gitURL) {
		log.Printf("[VALIDATION] Rejected non-whitelisted domain: %s", gitURL)
		http.Error(w, "Only whitelisted domains are allowed (github.com, gitlab.com)", http.StatusBadRequest)
		return
	}

	log.Printf("[VALIDATION] Domain validated successfully: %s", gitURL)

	lastID, err := h.repoStore.Create(name, gitURL, repoType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Database error: %v", err), http.StatusInternalServerError)
		return
	}

	// Use %q to quote user-supplied values so that embedded newlines, carriage
	// returns, or other control characters are escaped and cannot forge new
	// log lines (CWE-117 / Log Forging).
	log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, name, gitURL)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"id":      lastID,
		"message": "Repository created successfully",
	})
}

func (h *Handler) CloneRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	repoIDStr := r.FormValue("repo_id")
	if repoIDStr == "" {
		http.Error(w, "Missing repo_id parameter", http.StatusBadRequest)
		return
	}

	var repoID int
	fmt.Sscanf(repoIDStr, "%d", &repoID)

	repo, err := h.repoStore.GetByID(repoID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Database error: %v", err), http.StatusInternalServerError)
		return
	}
	if repo == nil {
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	result, err := h.gitService.Clone(repoID, repo.GitURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Clone failed: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"repo_id":   repoID,
		"name":      repo.Name,
		"git_url":   repo.GitURL,
		"clone_dir": result.TargetDir,
		"head":      result.HeadHash,
		"files":     result.Files,
	}

	json.NewEncoder(w).Encode(response)
}

// ListRepos handles listing all repositories
func (h *Handler) ListRepos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	repos, err := h.repoStore.List()
	if err != nil {
		http.Error(w, fmt.Sprintf("Database error: %v", err), http.StatusInternalServerError)
		return
	}

	if repos == nil {
		repos = []*models.Repository{}
	}

	// Convert to map format for backward compatibility
	var repoMaps []map[string]interface{}
	for _, repo := range repos {
		repoMaps = append(repoMaps, map[string]interface{}{
			"id":        repo.ID,
			"name":      repo.Name,
			"git_url":   repo.GitURL,
			"repo_type": repo.RepoType,
			"created":   repo.Created,
		})
	}

	json.NewEncoder(w).Encode(repoMaps)
}
