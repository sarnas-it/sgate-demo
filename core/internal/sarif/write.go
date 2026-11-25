package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

type logFile struct {
	Version string   `json:"version"`
	Schema  string   `json:"$schema"`
	Runs    []logRun `json:"runs"`
}

type logRun struct {
	Tool    logTool     `json:"tool"`
	Results []logResult `json:"results"`
}

type logTool struct {
	Driver logDriver `json:"driver"`
}

type logDriver struct {
	Name  string    `json:"name"`
	Rules []logRule `json:"rules"`
}

type logRule struct {
	ID                   string               `json:"id"`
	ShortDescription     logText              `json:"shortDescription"`
	DefaultConfiguration defaultConfiguration `json:"defaultConfiguration"`
	Properties           map[string]any       `json:"properties,omitempty"`
}

type logText struct {
	Text string `json:"text"`
}

type logResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             logText           `json:"message"`
	Locations           []logLocation     `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Suppressions        []logSuppression  `json:"suppressions,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type logLocation struct {
	PhysicalLocation logPhysical `json:"physicalLocation"`
}

type logPhysical struct {
	ArtifactLocation logArtifact `json:"artifactLocation"`
	Region           logRegion   `json:"region"`
}

type logArtifact struct {
	URI string `json:"uri"`
}

type logRegion struct {
	StartLine int `json:"startLine"`
}

type logSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// Write собирает SARIF 2.1.0 из нормализованных находок SGATE.
func Write(w io.Writer, findings []Finding, toolName string) error {
	if toolName == "" {
		toolName = "SGATE"
	}
	ruleIndex := map[string]int{}
	rules := make([]logRule, 0)
	results := make([]logResult, 0, len(findings))
	for _, f := range findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			r := logRule{
				ID:                   f.RuleID,
				ShortDescription:     logText{Text: f.Message},
				DefaultConfiguration: defaultConfiguration{Level: sarifLevel(f.Severity)},
			}
			if f.Description != "" || f.GOSTType != "" || f.CWE != "" {
				r.Properties = map[string]any{}
				if f.Description != "" {
					r.Properties["description"] = f.Description
				}
				if f.GOSTType != "" {
					r.Properties["gost_type"] = f.GOSTType
				}
				if f.CWE != "" {
					r.Properties["cwe"] = f.CWE
				}
			}
			rules = append(rules, r)
		}
		res := logResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   logText{Text: f.Message},
			Locations: []logLocation{{
				PhysicalLocation: logPhysical{
					ArtifactLocation: logArtifact{URI: f.File},
					Region:           logRegion{StartLine: f.Line},
				},
			}},
		}
		if f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{"sgate/v1": f.Fingerprint}
		}
		// 8.5: результат должен содержать тип ошибки и её описание.
		if f.GOSTType != "" || f.Description != "" || f.CWE != "" {
			res.Properties = map[string]any{}
			if f.GOSTType != "" {
				res.Properties["gost_type"] = f.GOSTType
			}
			if f.Description != "" {
				res.Properties["description"] = f.Description
			}
			if f.CWE != "" {
				res.Properties["cwe"] = f.CWE
			}
		}
		if f.Baseline {
			res.Suppressions = []logSuppression{{Kind: "external", Justification: "baseline"}}
		}
		results = append(results, res)
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	// после сортировки правил пересчитываем индексы
	for i := range rules {
		ruleIndex[rules[i].ID] = i
	}
	for i := range results {
		results[i].RuleIndex = ruleIndex[results[i].RuleID]
	}

	out := logFile{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []logRun{{
			Tool:    logTool{Driver: logDriver{Name: toolName, Rules: rules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	return nil
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
