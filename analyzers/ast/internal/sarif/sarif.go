// Package sarif печатает находки в SARIF 2.1.0 — единственный контракт
// между анализатором и SGATE. Модуль не импортирует core: тот же формат
// сможет отдавать анализатор на любом другом языке.
package sarif

import (
	"encoding/json"
	"fmt"
	"os"

	"code.sarnas.ru/sgate/analyzers/ast/internal/rules"
)

type report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
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
	ID                   string         `json:"id"`
	ShortDescription     text           `json:"shortDescription"`
	DefaultConfiguration config         `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type config struct {
	Level string `json:"level"`
}

type text struct {
	Text string `json:"text"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   text       `json:"message"`
	Locations []location `json:"locations"`
}

type location struct {
	PhysicalLocation physical `json:"physicalLocation"`
}

type physical struct {
	ArtifactLocation artifact `json:"artifactLocation"`
	Region           region   `json:"region"`
}

type artifact struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// Write сохраняет отчёт. Пустой список находок — валидный SARIF без results:
// SGATE отличает «чисто» от «не просканировано» по отдельному счётчику.
func Write(path string, findings []rules.Finding) error {
	catalog := rules.Catalog()
	rulesOut := make([]rule, 0, len(catalog))
	for _, r := range catalog {
		rulesOut = append(rulesOut, rule{
			ID:               r.ID,
			ShortDescription: text{Text: r.Message},
			DefaultConfiguration: config{
				Level: level(r.Severity),
			},
			Properties: map[string]any{
				"severity": r.Severity,
				"cwe":      r.CWE,
			},
		})
	}
	results := make([]result, 0, len(findings))
	for _, f := range findings {
		results = append(results, result{
			RuleID:  f.Rule,
			Level:   level(f.Severity),
			Message: text{Text: f.Message},
			Locations: []location{{
				PhysicalLocation: physical{
					ArtifactLocation: artifact{URI: f.File},
					Region:           region{StartLine: f.Line, StartColumn: f.Column},
				},
			}},
		})
	}
	rep := report{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []run{{
			Tool:    tool{Driver: driver{Name: "sgate-ast", Rules: rulesOut}},
			Results: results,
		}},
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	return nil
}

func level(severity string) string {
	switch severity {
	case "HIGH":
		return "error"
	case "LOW":
		return "note"
	default:
		return "warning"
	}
}
