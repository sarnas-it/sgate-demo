package quality

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.sarnas.ru/sgate/internal/sarif"
)

func near(a, b float64) bool { return math.Abs(a-b) < 0.001 }

func TestMeasureFormulas(t *testing.T) {
	m := Manifest{
		Version:   1,
		Tolerance: 2,
		Clean:     []string{"clean.go"},
		Defects: []Defect{
			{File: "a.go", Line: 10, Type: "6.3а"},
			{File: "b.go", Line: 20, Type: "6.3б"},
			{File: "c.go", Line: 30, Type: "6.3г"},
			{File: "d.go", Line: 40, Type: "6.3а"},
		},
	}
	findings := []sarif.Finding{
		{Analyzer: "gosec", RuleID: "G701", File: "a.go", Line: 11, GOSTType: "6.3а"},
		{Analyzer: "gosec", RuleID: "G115", File: "b.go", Line: 20, GOSTType: "6.3б"},
		{Analyzer: "gosec", RuleID: "G404", File: "noise.go", Line: 1, GOSTType: "6.3г"},
		{Analyzer: "gosec", RuleID: "G104", File: "clean.go", Line: 5, GOSTType: ""},
	}
	res := Measure(m, findings)
	if res.TB != 4 || res.TP != 2 || res.FN != 2 {
		t.Fatalf("TB=%d TP=%d FN=%d", res.TB, res.TP, res.FN)
	}
	if res.TW != 3 || res.FP != 1 {
		t.Fatalf("TW=%d FP=%d", res.TW, res.FP)
	}
	if !near(res.FNRate, 50) {
		t.Errorf("FN rate=%v, want 50", res.FNRate)
	}
	if !near(res.FPRate, 100.0/3) {
		t.Errorf("FP rate=%v, want 33.33", res.FPRate)
	}
	if res.Skipped != 1 {
		t.Errorf("некритические типы должны пропускаться: %d", res.Skipped)
	}
	if !res.Passed {
		t.Error("50/33 должен проходить порог 8.4")
	}
}

func TestMeasureDuplicateRuleIsNotFalsePositive(t *testing.T) {
	m := Manifest{Tolerance: 2, Defects: []Defect{{File: "crypto/md5.go", Line: 9, Type: "6.3г"}}}
	findings := []sarif.Finding{
		{Analyzer: "gosec", RuleID: "G501", File: "crypto/md5.go", Line: 4, GOSTType: "6.3г"},
		{Analyzer: "gosec", RuleID: "G401", File: "crypto/md5.go", Line: 9, GOSTType: "6.3г"},
	}
	res := Measure(m, findings)
	if res.FP != 0 {
		t.Fatalf("дубль правила того же дефекта не должен быть FP: %v", res.FalsePos)
	}
	if res.TP != 1 || res.FN != 0 {
		t.Fatalf("TP=%d FN=%d", res.TP, res.FN)
	}
}

func TestMeasureFailsAboveThreshold(t *testing.T) {
	m := Manifest{Tolerance: 2, Clean: []string{"clean.go"}, Defects: []Defect{{File: "a.go", Line: 1, Type: "6.3а"}}}
	findings := []sarif.Finding{
		{File: "clean.go", Line: 1, GOSTType: "6.3а", RuleID: "G701"},
		{File: "clean.go", Line: 5, GOSTType: "6.3г", RuleID: "G404"},
	}
	res := Measure(m, findings)
	if res.Passed {
		t.Fatal("2 FP из 2 предупреждений должны проваливать порог")
	}
}

func TestMarkdownMentionsFormulas(t *testing.T) {
	m := Manifest{Defects: []Defect{{File: "a.go", Line: 1, Type: "6.3а"}}}
	doc := Measure(m, nil).Markdown("Отчёт")
	for _, want := range []string{"10.4", "10.5", "ПРОЙДЕНО"} {
		if !contains(doc, want) {
			t.Errorf("в отчёте нет %q", want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestCorpusManifestMatchesMarkers защищает набор от рассинхронизации:
// строка из manifest.json должна содержать маркер с тем же типом 6.3.
func TestCorpusManifestMatchesMarkers(t *testing.T) {
	m, err := LoadManifest("../../testdata/gost-corpus/manifest.json")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(m.Defects) < 10 {
		t.Fatalf("в наборе %d ошибок, ожидалось не меньше 10 (10.2 а, б)", len(m.Defects))
	}
	for _, d := range m.Defects {
		raw, err := os.ReadFile(filepath.Join("../../testdata/gost-corpus", d.File))
		if err != nil {
			t.Fatalf("%s: %v", d.File, err)
		}
		lines := strings.Split(string(raw), "\n")
		if d.Line < 1 || d.Line > len(lines) {
			t.Fatalf("%s:%d вне файла", d.File, d.Line)
		}
		line := lines[d.Line-1]
		if !strings.Contains(line, "GOST:"+d.Type) {
			t.Errorf("%s:%d не содержит маркер GOST:%s: %q", d.File, d.Line, d.Type, line)
		}
	}
}
