package dast

import (
	"testing"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestDedup(t *testing.T) {
	in := []sarif.Finding{
		{Analyzer: "ferox", RuleID: "ferox-200", File: "http://x/a", Fingerprint: "fp1"},
		{Analyzer: "ferox", RuleID: "ferox-200", File: "http://x/a", Fingerprint: "fp1"},
		{Analyzer: "zap", RuleID: "10021", File: "http://x/a", Message: "m"},
		{Analyzer: "zap", RuleID: "10021", File: "http://x/a", Message: "m"},
		{Analyzer: "zap", RuleID: "10021", File: "http://x/b", Message: "m"},
		{Analyzer: "zap", RuleID: "10038", File: "http://x/c", CWE: "CWE-79", Message: "csp"},
		{Analyzer: "nuclei", RuleID: "csp-check", File: "http://x/c", CWE: "CWE-79", Message: "csp"},
	}
	got := Dedup(in)
	if len(got) != 4 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
}
