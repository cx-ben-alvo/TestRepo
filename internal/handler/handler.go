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

// repoCreator is the subset of repository.RepositoryStore used by the handler.
// It is defined as an interface to allow test stubs to be injected.
type repoCreator interface {
	Create(name, gitURL, repoType string) (int64, error)
	GetByID(id int) (*models.Repository, error)
	List() ([]*models.Repository, error)
}

type Handler struct {
	repoStore  repoCreator
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
		log.Printf("[VALIDATION] Rejected non-whitelisted domain: %q", gitURL)
		http.Error(w, "Only whitelisted domains are allowed (github.com, gitlab.com)", http.StatusBadRequest)
		return
	}

	log.Printf("[VALIDATION] Domain validated successfully: %q", gitURL)

	lastID, err := h.repoStore.Create(name, gitURL, repoType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Database error: %v", err), http.StatusInternalServerError)
		return
	}

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
