package runs

import (
	"testing"
	"time"

	"code.sarnas.ru/sgate/internal/marking"
	"code.sarnas.ru/sgate/internal/sarif"
)

func f(rule, file string, line int, fp string) sarif.Finding {
	return sarif.Finding{Analyzer: "gosec", RuleID: rule, File: file, Line: line, Fingerprint: fp}
}

func TestSaveLoad(t *testing.T) {
	root := t.TempDir()
	r := Run{
		Meta:     Meta{ID: "20260101T000000", Analyzers: []string{"gosec"}, Total: 2},
		Findings: []sarif.Finding{f("G304", "a.go", 10, "p1"), f("G115", "b.go", 3, "p2")},
	}
	dir, err := Save(root, r)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Meta.ID != r.Meta.ID || len(got.Findings) != 2 {
		t.Fatalf("запуск не восстановлен: %+v", got.Meta)
	}
	latest, err := Latest(root)
	if err != nil || latest != dir {
		t.Fatalf("latest=%q err=%v", latest, err)
	}
}

func TestCompareGroups(t *testing.T) {
	prev := Run{Findings: []sarif.Finding{
		f("G304", "a.go", 10, "same"),
		f("G115", "gone.go", 5, "gone"),
		f("G101", "fp.go", 1, "fpkey"),
	}}
	cur := Run{Findings: []sarif.Finding{
		f("G304", "a.go", 10, "same"),
		f("G705", "new.go", 7, "new"),
		f("G101", "fp.go", 1, "fpkey"),
	}}
	marks := &marking.Store{Version: 1, Marks: map[string]marking.Mark{}}
	marks.Set(f("G101", "fp.go", 1, "fpkey"), marking.Mark{Category: marking.False})
	d := Compare(prev, cur, marks)
	if len(d.Both) != 2 {
		t.Errorf("both=%d, want 2", len(d.Both))
	}
	if len(d.OnlyPrev) != 1 || d.OnlyPrev[0].Fingerprint != "gone" {
		t.Errorf("only previous=%v", d.OnlyPrev)
	}
	if len(d.OnlyCur) != 1 || d.OnlyCur[0].Fingerprint != "new" {
		t.Errorf("only current=%v", d.OnlyCur)
	}
	if len(d.HiddenFP) != 1 || d.HiddenFP[0].Fingerprint != "fpkey" {
		t.Errorf("hidden false positive=%v", d.HiddenFP)
	}
}

func TestNewIDFormat(t *testing.T) {
	id := NewID(time.Date(2026, 11, 24, 20, 55, 12, 0, time.UTC))
	if id != "20261124T205512" {
		t.Fatalf("id=%q", id)
	}
}

func TestLatestEmpty(t *testing.T) {
	if _, err := Latest(t.TempDir()); err == nil {
		t.Fatal("ожидалась ошибка на пустом хранилище")
	}
}
