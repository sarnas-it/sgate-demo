package sarif

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRoundTrip(t *testing.T) {
	findings := []Finding{
		{Analyzer: "semgrep", RuleID: "r1", Severity: "high", Message: "m1", File: "a.go", Line: 3, Fingerprint: "fp1"},
		{Analyzer: "bandit", RuleID: "B602", Severity: "medium", Message: "m2", File: "app.py", Line: 5, Baseline: true},
	}
	var buf bytes.Buffer
	if err := Write(&buf, findings, "SGATE"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(path, "sgate")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d", len(got))
	}
	if got[0].Severity != "high" || got[0].File != "a.go" || got[0].Line != 3 {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Severity != "medium" || got[1].Line != 5 {
		t.Errorf("second = %+v", got[1])
	}
}
