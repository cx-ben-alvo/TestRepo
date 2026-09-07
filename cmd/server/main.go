package main

import (
	"fmt"
	"log"
	http26 "net/http"
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

	// Register routes — all responses include a Content-Security-Policy header
	// via the WithCSP middleware wrapper (CWE-346).
	http26.HandleFunc("/api/repo/create", handler.WithCSP(h.CreateRepo))
	http26.HandleFunc("/api/repo/clone", handler.WithCSP(h.CloneRepo))
	http26.HandleFunc("/api/repo/list", handler.WithCSP(h.ListRepos))

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// Require TLS certificate and key to prevent plain-text (HTTP) transport.
	// Both paths must be supplied via TLS_CERT_FILE and TLS_KEY_FILE environment
	// variables. Using ListenAndServeTLS ensures all traffic is encrypted with
	// SSL/TLS, protecting against Man-in-the-Middle attacks (CWE-319).
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE environment variables must be set to enable HTTPS")
	}
	log.Fatal(http26.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
