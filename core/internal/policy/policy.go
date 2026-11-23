// Package policy применяет порог блокировки к находкам.
package policy

import (
	"strings"

	"code.sarnas.ru/sgate/internal/sarif"
)

var rank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// Rank возвращает вес severity; неизвестное — 0.
func Rank(severity string) int {
	return rank[strings.ToLower(severity)]
}

// Blocking возвращает находки, которые не ниже порога.
func Blocking(findings []sarif.Finding, threshold string) []sarif.Finding {
	limit := Rank(threshold)
	out := make([]sarif.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Baseline {
			continue
		}
		if Rank(f.Severity) >= limit {
			out = append(out, f)
		}
	}
	return out
}
