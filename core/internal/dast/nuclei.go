package dast

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"code.sarnas.ru/sgate/internal/sarif"
)

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string         `json:"name"`
		Severity       string         `json:"severity"`
		Classification map[string]any `json:"classification"`
	} `json:"info"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	MatcherName string `json:"matcher-name"`
}

// ParseNucleiJSONL читает JSONL-вывод nuclei.
func ParseNucleiJSONL(path, analyzerID string) ([]sarif.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read nuclei jsonl: %w", err)
	}
	defer f.Close()
	var out []sarif.Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r nucleiResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		loc := r.MatchedAt
		if loc == "" {
			loc = r.Host
		}
		finding := sarif.Finding{
			Analyzer: analyzerID,
			RuleID:   r.TemplateID,
			Severity: severityFromNuclei(r.Info.Severity),
			CWE:      normalizeCWE(r.Info.Classification["cwe-id"]),
			Message:  cleanMessage(r.Info.Name + " " + r.MatcherName),
			File:     loc,
			Line:     1,
		}
		sum := sha1.Sum([]byte(analyzerID + "|" + r.TemplateID + "|" + loc + "|" + r.MatcherName))
		finding.Fingerprint = hex.EncodeToString(sum[:])
		out = append(out, finding)
	}
	return out, sc.Err()
}

func severityFromNuclei(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}
