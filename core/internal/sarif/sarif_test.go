package sarif

import (
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	got, err := Parse("../../testdata/semgrep.sarif", "semgrep")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d", len(got))
	}
	if got[0].Severity != "critical" || got[0].File != "sast/go/main.go" || got[0].Line != 10 {
		t.Errorf("first finding = %+v", got[0])
	}
	if got[0].Fingerprint != "go-1" {
		t.Errorf("fingerprint = %q", got[0].Fingerprint)
	}
	if got[1].Severity != "high" {
		t.Errorf("second severity = %q", got[1].Severity)
	}
}

func TestParseDefaultConfigurationLevel(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/default-level.sarif"
	raw := `{"runs":[{"tool":{"driver":{"rules":[{"id":"r1","defaultConfiguration":{"level":"error"}}]}},"results":[{"ruleId":"r1","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("got %+v", got)
	}
}

// TestFingerprintStableAcrossLineShift — отпечаток не должен меняться при
// сдвиге строки: иначе разметка (5.5) и сравнение запусков (8.9) теряются.
func TestFingerprintStableAcrossLineShift(t *testing.T) {
	a := hashFingerprint("gosec", "G304", "a.go", "Potential file inclusion via variable")
	b := hashFingerprint("gosec", "G304", "a.go", "Potential file inclusion via variable")
	if a != b {
		t.Fatal("отпечаток нестабилен")
	}
	if hashFingerprint("gosec", "G304", "b.go", "Potential file inclusion via variable") == a {
		t.Fatal("отпечаток не учитывает файл")
	}
}
