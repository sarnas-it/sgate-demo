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

type feroxEntry struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// ParseFeroxJSON читает JSONL-вывод feroxbuster и оставляет найденные пути.
func ParseFeroxJSON(path, analyzerID string) ([]sarif.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read ferox json: %w", err)
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
		var e feroxEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Type != "" && e.Type != "response" {
			continue
		}
		if e.URL == "" || e.Status == 404 {
			continue
		}
		sev := "info"
		if e.Status == 401 || e.Status == 403 {
			sev = "low"
		}
		finding := sarif.Finding{
			Analyzer: analyzerID,
			RuleID:   fmt.Sprintf("ferox-%d", e.Status),
			Severity: sev,
			Message:  fmt.Sprintf("обнаружен путь: HTTP %d", e.Status),
			File:     e.URL,
			Line:     1,
		}
		sum := sha1.Sum([]byte(analyzerID + "|" + e.URL + "|" + fmt.Sprint(e.Status)))
		finding.Fingerprint = hex.EncodeToString(sum[:])
		out = append(out, finding)
	}
	return out, sc.Err()
}
