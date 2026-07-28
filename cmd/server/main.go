package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/checkmarx/correlation-demo/internal/config"
	"github.com/checkmarx/correlation-demo/internal/database"
	"github.com/checkmarx/correlation-demo/internal/handler"
	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize directories
	initDirs(cfg)

	// Initialize database
	db, err := database.InitDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialize dependencies
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	gitService := service.NewGitService(cfg.CloneDir)

	// Initialize handler
	h := handler.NewHandler(repoStore, validator, gitService)

	// Register routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/repo/create", h.CreateRepo)
	mux.HandleFunc("/api/repo/clone", h.CloneRepo)
	mux.HandleFunc("/api/repo/list", h.ListRepos)

	// Start server
	fmt.Printf("Server starting on %s (TLS)\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// Use ListenAndServeTLS to encrypt all traffic with TLS (fixes CWE-319:
	// Cleartext Transmission of Sensitive Information). The certificate and
	// key paths are read from the TLS_CERT_FILE / TLS_KEY_FILE environment
	// variables (or the defaults set in config.Load).
	// Wrap the mux with the HSTS middleware to instruct browsers to always
	// use HTTPS for this host (fixes CWE-346: Missing HSTS Header).
	log.Fatal(http.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, hstsMiddleware(mux)))
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}

// hstsMiddleware wraps an http.Handler and sets the Strict-Transport-Security
// header on every response, instructing browsers to only connect over HTTPS
// for the next two years and to include subdomains (CWE-346).
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// max-age=63072000 is two years in seconds; includeSubDomains ensures
		// that subdomains are also covered by the HSTS policy.
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}
