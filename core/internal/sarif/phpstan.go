package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
)

type phpstanReport struct {
	Files map[string]struct {
		Messages []struct {
			Message    string `json:"message"`
			Line       int    `json:"line"`
			Identifier string `json:"identifier"`
		} `json:"messages"`
	} `json:"files"`
}

// ParsePHPStanJSON читает JSON PHPStan (--error-format=json).
// PHPStan не даёт severity: это статические замечания, поэтому medium.
func ParsePHPStanJSON(file, analyzerID string) ([]Finding, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read phpstan json: %w", err)
	}
	var r phpstanReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse phpstan json: %w", err)
	}
	var out []Finding
	for filePath, f := range r.Files {
		clean := path.Clean(filePath)
		clean = strings.TrimPrefix(clean, "/app/")
		clean = strings.TrimPrefix(clean, "/src/")
		for _, m := range f.Messages {
			finding := Finding{
				Analyzer: analyzerID,
				RuleID:   m.Identifier,
				Severity: "medium",
				Message:  m.Message,
				File:     clean,
				Line:     m.Line,
			}
			finding.Fingerprint = hashFingerprint(analyzerID, m.Identifier, clean, fmt.Sprint(m.Line), m.Message)
			out = append(out, finding)
		}
	}
	return out, nil
}
