// Package sarif читает SARIF 2.1.0 в единую модель находок SGATE.
package sarif

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

// Finding — нормализованная находка любого анализатора.
type Finding struct {
	Analyzer    string `json:"analyzer"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Fingerprint string `json:"fingerprint"`
}

type report struct {
	Runs []run `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name  string `json:"name"`
	Rules []rule `json:"rules"`
}

type rule struct {
	ID                   string               `json:"id"`
	Properties           map[string]any       `json:"properties"`
	DefaultConfiguration defaultConfiguration `json:"defaultConfiguration"`
}

type defaultConfiguration struct {
	Level string `json:"level"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Fingerprints        map[string]string `json:"fingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}

// Parse читает SARIF-файл и возвращает находки. Пустой runs/results — не ошибка.
func Parse(file, analyzerID string) ([]Finding, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read sarif: %w", err)
	}
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}
	var out []Finding
	for _, run := range r.Runs {
		sevByRule := map[string]string{}
		for _, rule := range run.Tool.Driver.Rules {
			sev := severityFromProperties(rule.Properties)
			if sev == "" {
				sev = severityFromLevel(rule.DefaultConfiguration.Level)
			}
			sevByRule[rule.ID] = sev
		}
		for _, res := range run.Results {
			sev := severityFromProperties(res.Properties)
			if sev == "" {
				sev = sevByRule[res.RuleID]
			}
			if sev == "" {
				sev = severityFromLevel(res.Level)
			}
			filePath, line := locationOf(res)
			fp := fingerprint(res, analyzerID, filePath, line)
			out = append(out, Finding{
				Analyzer:    analyzerID,
				RuleID:      res.RuleID,
				Severity:    sev,
				Message:     strings.TrimSpace(res.Message.Text),
				File:        filePath,
				Line:        line,
				Fingerprint: fp,
			})
		}
	}
	return out, nil
}

func locationOf(res result) (string, int) {
	if len(res.Locations) == 0 {
		return "", 0
	}
	pl := res.Locations[0].PhysicalLocation
	return cleanPath(pl.ArtifactLocation.URI), pl.Region.StartLine
}

func cleanPath(uri string) string {
	uri = strings.TrimPrefix(uri, "file://")
	uri = strings.TrimPrefix(uri, "/src/")
	uri = strings.TrimPrefix(uri, "./")
	return path.Clean(uri)
}

func severityFromLevel(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "info"
	}
}

// severityFromProperties понимает security-severity (CVSS) и severity (ERROR/WARNING).
func severityFromProperties(props map[string]any) string {
	if props == nil {
		return ""
	}
	if v, ok := props["security-severity"]; ok {
		if score, ok := toFloat(v); ok {
			switch {
			case score >= 9.0:
				return "critical"
			case score >= 7.0:
				return "high"
			case score >= 4.0:
				return "medium"
			case score > 0:
				return "low"
			}
		}
	}
	if v, ok := props["severity"]; ok {
		if s, ok := v.(string); ok {
			switch strings.ToLower(s) {
			case "critical":
				return "critical"
			case "error", "high":
				return "high"
			case "warning", "medium":
				return "medium"
			case "note", "low":
				return "low"
			}
		}
	}
	return ""
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func fingerprint(res result, analyzerID, file string, line int) string {
	for _, m := range []map[string]string{res.PartialFingerprints, res.Fingerprints} {
		for _, key := range []string{"primaryLocationLineHash", "matchBasedId/v1"} {
			if v := m[key]; v != "" && v != "requires login" {
				return v
			}
		}
	}
	sum := sha1.Sum([]byte(fmt.Sprintf("%s|%s|%s|%d|%s", analyzerID, res.RuleID, file, line, res.Message.Text)))
	return hex.EncodeToString(sum[:])
}
