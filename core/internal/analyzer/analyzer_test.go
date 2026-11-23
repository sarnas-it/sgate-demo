package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/config"
)

func TestRunCommand(t *testing.T) {
	repo := t.TempDir()
	out := t.TempDir()
	src, err := os.ReadFile("../../testdata/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "fixture.sarif"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	spec := config.Analyzer{
		ID:      "fake",
		Runtime: "command",
		Command: []string{"sh", "-c", `cp "$SGATE_REPO/fixture.sarif" "$SGATE_OUT"`},
		Output:  "out.sarif",
		Timeout: "5s",
		Network: "none",
	}
	path, err := Run(context.Background(), spec, repo, repo, out, "")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(repo, "out.sarif") {
		t.Fatalf("path = %q", path)
	}
}

func TestLinkedGitRoot(t *testing.T) {
	base := t.TempDir()
	gitRoot := filepath.Join(base, ".git")
	wtDir := filepath.Join(base, "wt")
	if err := os.MkdirAll(filepath.Join(gitRoot, "worktrees", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wtDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wtDir, ".git"), []byte("gitdir: "+filepath.Join(gitRoot, "worktrees", "x")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := linkedGitRoot(wtDir)
	if !ok || got != gitRoot {
		t.Fatalf("got %q ok=%v, want %q", got, ok, gitRoot)
	}
	if _, ok := linkedGitRoot(t.TempDir()); ok {
		t.Fatal("normal dir must not be a linked worktree")
	}
}
