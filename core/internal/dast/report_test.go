package dast

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestWriteMarkdown(t *testing.T) {
	var b bytes.Buffer
	r := Report{
		Target:   "http://127.0.0.1:3000",
		Date:     time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
		Scanners: []string{"zap-baseline", "nuclei"},
		Findings: []sarif.Finding{
			{Severity: "high", RuleID: "r1", File: "http://x/a", Message: "m1"},
			{Severity: "medium", RuleID: "r2", File: "http://x/b", Message: "m2"},
		},
		Blocking: 1,
		Warnings: 1,
	}
	if err := WriteMarkdown(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"DAST-отчёт", "http://127.0.0.1:3000", "high", "Покрытие OWASP WSTG", "ATHZ", "не проверено"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}
