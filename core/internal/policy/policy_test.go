package policy

import (
	"testing"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestBlocking(t *testing.T) {
	f := []sarif.Finding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
	}
	if got := len(Blocking(f, "high")); got != 2 {
		t.Fatalf("blocking = %d", got)
	}
	if got := len(Blocking(f, "medium")); got != 3 {
		t.Fatalf("blocking medium = %d", got)
	}
	f[0].Baseline = true
	if got := len(Blocking(f, "critical")); got != 0 {
		t.Fatalf("baseline finding must not block, got %d", got)
	}
}
