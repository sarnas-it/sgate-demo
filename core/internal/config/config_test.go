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

// TestLoadScannedRegexDefaults — при заданном scanned_regex минимум файлов по
// умолчанию 1: «ни одного файла» — это сбой, а не «чисто».
func TestLoadScannedRegexDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "analyzers.yaml")
	raw := `version: 1
analyzers:
  - id: gosec
    languages: [go]
    runtime: command
    command: [gosec]
    output: /out/gosec.sarif
    scanned_regex: 'Checking file: (\S+)'
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Analyzers[0].MinScannedFiles != 1 {
		t.Fatalf("MinScannedFiles = %d, want 1", c.Analyzers[0].MinScannedFiles)
	}
}

// TestLoadRejectsBadScannedRegex — опечатка в регулярке должна падать на
// старте, а не молча отключать проверку покрытия.
func TestLoadRejectsBadScannedRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "analyzers.yaml")
	raw := `version: 1
analyzers:
  - id: gosec
    languages: [go]
    runtime: command
    command: [gosec]
    output: /out/gosec.sarif
    scanned_regex: 'Checking file: (\S+'
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("ожидалась ошибка компиляции scanned_regex")
	}
}

// TestLoadRejectsScannedRegexWithoutGroup — без группы нечего считать.
func TestLoadRejectsScannedRegexWithoutGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "analyzers.yaml")
	raw := `version: 1
analyzers:
  - id: gosec
    languages: [go]
    runtime: command
    command: [gosec]
    output: /out/gosec.sarif
    scanned_regex: 'Checking file: \S+'
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("ожидалась ошибка: у регулярки нет группы захвата")
	}
}

// TestLoadScannedTotalRequiresRegex — scanned_total без scanned_regex
// бессмыслен: читать число неоткуда. Опечатка должна падать на старте.
func TestLoadScannedTotalRequiresRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "analyzers.yaml")
	raw := `version: 1
analyzers:
  - id: semgrep
    languages: [go]
    runtime: command
    command: [semgrep]
    output: /out/semgrep.sarif
    scanned_total: true
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("ожидалась ошибка: scanned_total без scanned_regex")
	}
}
