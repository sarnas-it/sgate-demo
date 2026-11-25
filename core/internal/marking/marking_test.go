package marking

import (
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "markings.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if len(s.Marks) != 0 {
		t.Fatal("отсутствующий файл должен давать пустую разметку")
	}
	f := sarif.Finding{Analyzer: "gosec", RuleID: "G304", File: "a.go", Line: 10, Fingerprint: "abc"}
	s.Set(f, Mark{Category: False, Comment: "тест"})
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m, ok := got.Get(f)
	if !ok || m.Category != False || m.File != "a.go" {
		t.Fatalf("разметка не восстановлена: %+v ok=%v", m, ok)
	}
}

func TestApplySetsCategory(t *testing.T) {
	s := &Store{Version: 1, Marks: map[string]Mark{}}
	f := sarif.Finding{Analyzer: "gosec", RuleID: "G115", File: "b.go", Line: 5, Fingerprint: "fp1"}
	s.Set(f, Mark{Category: Accepted, Owner: "team", Comment: "до 2026-12-31"})
	findings := []sarif.Finding{f}
	s.Apply(findings)
	if findings[0].Marking != string(Accepted) {
		t.Fatalf("Marking=%q", findings[0].Marking)
	}
}

func TestKeyStableWithoutFingerprint(t *testing.T) {
	a := sarif.Finding{Analyzer: "gosec", RuleID: "G101", File: "x.go", Line: 1, Message: "m"}
	b := a
	b.Line = 99 // сдвиг строк не должен менять ключ без fingerprint
	if Key(a) != Key(b) {
		t.Fatal("ключ без fingerprint не должен зависеть от строки")
	}
}

func TestCategoryValid(t *testing.T) {
	for _, c := range []Category{True, False, Accepted} {
		if !c.Valid() {
			t.Errorf("%q должна быть допустимой", c)
		}
	}
	if Category("maybe").Valid() {
		t.Error("произвольная категория не должна приниматься")
	}
}
