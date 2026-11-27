package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpusgenManifest — манифест должен описывать ровно те строки, которые
// генератор реально записал: иначе sgate quality посчитает ложные пропуски.
func TestCorpusgenManifest(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "corpus")

	oldArgs := os.Args
	os.Args = []string{"corpusgen", "-out", out, "-defect-files", "2", "-clean-files", "1", "-file-lines", "80"}
	defer func() { os.Args = oldArgs }()

	// main вызывает os.Exit только при ошибках; здесь директория валидна.
	main()

	raw, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != 1 || m.Tolerance != 2 {
		t.Fatalf("manifest header = %+v", m)
	}
	if len(m.Clean) != 1 {
		t.Fatalf("clean = %v", m.Clean)
	}
	// По 8 ошибок на пакет × 2 пакета.
	if len(m.Defects) != 16 {
		t.Fatalf("defects = %d, want 16", len(m.Defects))
	}

	for _, d := range m.Defects {
		path := filepath.Join(out, filepath.FromSlash(d.File))
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", d.File, err)
		}
		lines := strings.Split(string(src), "\n")
		if d.Line < 1 || d.Line > len(lines) {
			t.Fatalf("%s:%d вне файла (%d строк)", d.File, d.Line, len(lines))
		}
		if d.Type == "" || d.CWE == "" {
			t.Fatalf("неполный дефект: %+v", d)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module corpus\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "go.mod")); err != nil {
		t.Fatalf("в корпусе нет go.mod: %v", err)
	}
}
