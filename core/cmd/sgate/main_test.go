package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/config"
	"code.sarnas.ru/sgate/internal/sarif"
)

func TestIsExcluded(t *testing.T) {
	patterns := []string{"core/testdata/**", "fixtures/*.py"}
	cases := map[string]bool{
		"core/testdata/python-bandit/app.py": true,
		"core/testdata/semgrep.sarif":        true,
		"fixtures/a.py":                      true,
		"fixtures/sub/a.py":                  false,
		"sast/go/main.go":                    false,
	}
	for file, want := range cases {
		if got := isExcluded(file, patterns); got != want {
			t.Errorf("%s: got %v want %v", file, got, want)
		}
	}
}

func TestFilterChanged(t *testing.T) {
	findings := []sarif.Finding{
		{File: "a.go"},
		{File: "dir/b.go"},
		{File: "c.go"},
	}
	got := filterChanged(findings, map[string]bool{"a.go": true, "dir/b.go": true})
	if len(got) != 2 || got[0].File != "a.go" || got[1].File != "dir/b.go" {
		t.Fatalf("got %+v", got)
	}
}

func TestChangedFiles(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-qm", "a")
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package b"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-qm", "b")
	files, err := changedFiles(dir, "HEAD~1", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if !files["b.go"] || files["a.go"] {
		t.Fatalf("files = %v", files)
	}
}

func TestCacheKeyStable(t *testing.T) {
	spec := config.Analyzer{ID: "x", Image: "img@sha256:abc", Command: []string{"run"}}
	a := cacheKey(spec, "commit")
	b := cacheKey(spec, "commit")
	if a != b {
		t.Fatal("cache key must be stable")
	}
	if a == cacheKey(spec, "other") {
		t.Fatal("cache key must depend on commit")
	}
}
