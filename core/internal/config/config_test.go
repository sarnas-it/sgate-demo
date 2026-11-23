package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "analyzers.yaml")
	raw := `version: 1
analyzers:
  - id: semgrep
    languages: [go, php]
    image: semgrep/semgrep:1.186.0
    command: [semgrep, scan]
    output: /out/out.sarif
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Analyzers) != 1 || c.Analyzers[0].ID != "semgrep" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if c.Analyzers[0].Runtime != "docker" {
		t.Fatalf("default runtime = %q", c.Analyzers[0].Runtime)
	}
	if c.Analyzers[0].Timeout != "10m" {
		t.Fatalf("default timeout = %q", c.Analyzers[0].Timeout)
	}
	if c.Analyzers[0].Format != "sarif" {
		t.Fatalf("default format = %q", c.Analyzers[0].Format)
	}
}

func TestLoadRejectsDuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "analyzers.yaml")
	raw := `version: 1
analyzers:
  - id: a
    languages: [go]
    command: [x]
    output: /out/a.sarif
  - id: a
    languages: [php]
    command: [x]
    output: /out/b.sarif
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate error")
	}
}
