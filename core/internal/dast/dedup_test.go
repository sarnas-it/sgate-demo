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
	}
	got := Dedup(in)
	if len(got) != 3 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
}
