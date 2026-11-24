package dast

import "code.sarnas.ru/sgate/internal/sarif"

// Dedup убирает точные повторы (один fingerprint или один набор
// analyzer+rule+file+message). Разные сканеры с разными правилами на один URL
// остаются: это разные находки, их склейка — отдельный шаг.
func Dedup(findings []sarif.Finding) []sarif.Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]sarif.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Fingerprint
		if key == "" {
			key = f.Analyzer + "|" + f.RuleID + "|" + f.File + "|" + f.Message
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
