package service

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
)

// GitService handles git operations
type GitService struct {
	cloneDir string
}

// NewGitService creates a new git service
func NewGitService(cloneDir string) *GitService {
	return &GitService{cloneDir: cloneDir}
}

// CloneResult contains the result of a clone operation
type CloneResult struct {
	TargetDir string
	HeadHash  string
	Files     []string
}

func (g *GitService) Clone(repoID int, gitURL string) (*CloneResult, error) {
	targetDir := filepath.Join(g.cloneDir, fmt.Sprintf("repo_%d", repoID))
	os.MkdirAll(targetDir, 0755)

	gitRepo, err := git.PlainClone(targetDir, false, &git.CloneOptions{
		URL:      gitURL,
		Progress: os.Stdout,
	})

	if err != nil {
		log.Printf("Clone error: %v", err)
		return nil, err
	}

	ref, _ := gitRepo.Head()

	files, _ := filepath.Glob(filepath.Join(targetDir, "*"))
	var fileList []string
	for _, f := range files {
		fileList = append(fileList, filepath.Base(f))
	}

	return &CloneResult{
		TargetDir: targetDir,
		HeadHash:  ref.Hash().String()[:8],
		Files:     fileList,
	}, nil
}
