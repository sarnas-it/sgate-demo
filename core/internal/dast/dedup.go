package dast

import (
	"code.sarnas.ru/sgate/internal/policy"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Dedup убирает точные повторы и склеивает ZAP/nuclei на один URL с одним CWE.
// Разные CWE или разные URL остаются раздельно.
func Dedup(findings []sarif.Finding) []sarif.Finding {
	seen := make(map[string]int, len(findings))
	out := make([]sarif.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Fingerprint
		if f.CWE != "" {
			key = f.File + "|" + f.CWE
		}
		if key == "" {
			key = f.Analyzer + "|" + f.RuleID + "|" + f.File + "|" + f.Message
		}
		if idx, ok := seen[key]; ok {
			if policy.Rank(f.Severity) > policy.Rank(out[idx].Severity) {
				out[idx] = f
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	return out
}
