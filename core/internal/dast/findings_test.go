package dast

import (
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestFindingsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.jsonl")
	in := []sarif.Finding{{Analyzer: "zap", RuleID: "r1", Severity: "high", File: "http://x"}}
	if err := AppendFindings(path, in); err != nil {
		t.Fatal(err)
	}
	if err := AppendFindings(path, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RuleID != "r1" {
		t.Fatalf("got %+v", got)
	}
}
