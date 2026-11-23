package baseline

import (
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestSaveLoadMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	f := sarif.Finding{Analyzer: "semgrep", RuleID: "r1", Severity: "high", File: "a.go", Line: 10, Fingerprint: "fp1"}
	if err := Save(path, []sarif.Finding{f}); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Match(f) {
		t.Fatal("saved finding must match")
	}
	other := f
	other.Fingerprint = "fp2"
	if b.Match(other) {
		t.Fatal("different fingerprint must not match")
	}
}

func TestFallbackKey(t *testing.T) {
	b := &Baseline{Version: 1, Findings: []Entry{{Analyzer: "bandit", RuleID: "B602", File: "app.py", Message: "x"}}}
	if !b.Match(sarif.Finding{Analyzer: "bandit", RuleID: "B602", File: "app.py", Message: "x"}) {
		t.Fatal("fallback key must match")
	}
	if b.Match(sarif.Finding{Analyzer: "bandit", RuleID: "B602", File: "app.py", Message: "y"}) {
		t.Fatal("different message must not match")
	}
}
