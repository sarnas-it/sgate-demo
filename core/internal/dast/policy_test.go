package dast

import (
	"testing"
	"time"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestPolicyEvaluate(t *testing.T) {
	p := &Policy{Block: []string{"critical", "high"}, Warn: []string{"medium"}}
	f := []sarif.Finding{
		{Severity: "high", RuleID: "r1", File: "http://x/a"},
		{Severity: "medium", RuleID: "r2", File: "http://x/a"},
		{Severity: "low", RuleID: "r3", File: "http://x/a"},
	}
	blocking, warnings, excepted := p.Evaluate(f)
	if len(blocking) != 1 || len(warnings) != 1 || excepted != 0 {
		t.Fatalf("blocking=%d warnings=%d excepted=%d", len(blocking), len(warnings), excepted)
	}
}

func TestPolicyException(t *testing.T) {
	tomorrow := time.Now().Add(48 * time.Hour).Format("2006-01-02")
	p := &Policy{
		Block: []string{"high"},
		Warn:  []string{"medium"},
		Exceptions: []Exception{{
			Rule: "r1", Path: "/health", Owner: "ИБ", Expires: tomorrow, Reason: "health endpoint",
		}},
	}
	f := []sarif.Finding{{Severity: "high", RuleID: "r1", File: "http://x/health"}}
	blocking, _, excepted := p.Evaluate(f)
	if len(blocking) != 0 || excepted != 1 {
		t.Fatalf("blocking=%d excepted=%d", len(blocking), excepted)
	}
}

func TestPolicyExpiredException(t *testing.T) {
	p := &Policy{
		Block: []string{"high"}, Warn: []string{"medium"},
		Exceptions: []Exception{{Rule: "r1", Owner: "ИБ", Expires: "2020-01-01"}},
	}
	blocking, _, excepted := p.Evaluate([]sarif.Finding{{Severity: "high", RuleID: "r1", File: "http://x/a"}})
	if len(blocking) != 1 || excepted != 0 {
		t.Fatalf("blocking=%d excepted=%d", len(blocking), excepted)
	}
}
