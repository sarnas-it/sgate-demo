// Package baseline хранит принятые находки и не даёт им блокировать новые PR.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"code.sarnas.ru/sgate/internal/sarif"
)

// Entry — принятая находка. Fingerprint — основной ключ; остальные поля нужны
// для читаемого diff и для анализаторов без fingerprint.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	Analyzer    string `json:"analyzer"`
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`
	Message     string `json:"message"`
}

// Baseline — файл принятых находок.
type Baseline struct {
	Version  int     `json:"version"`
	Findings []Entry `json:"findings"`
}

func (e Entry) key() string {
	if e.Fingerprint != "" {
		return "fp:" + e.Fingerprint
	}
	return "raw:" + e.Analyzer + "|" + e.RuleID + "|" + e.File + "|" + e.Message
}

func findingKey(f sarif.Finding) string {
	if f.Fingerprint != "" {
		return "fp:" + f.Fingerprint
	}
	return "raw:" + f.Analyzer + "|" + f.RuleID + "|" + f.File + "|" + f.Message
}

// Load читает baseline. Отсутствующий файл — ошибка: явный baseline не должен
// молча превращаться в «всё новое».
func Load(path string) (*Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if b.Version != 1 {
		return nil, fmt.Errorf("unsupported baseline version %d", b.Version)
	}
	return &b, nil
}

// Save записывает текущие находки как принятые.
func Save(path string, findings []sarif.Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b := Baseline{Version: 1, Findings: make([]Entry, 0, len(findings))}
	for _, f := range findings {
		b.Findings = append(b.Findings, Entry{
			Fingerprint: f.Fingerprint,
			Analyzer:    f.Analyzer,
			RuleID:      f.RuleID,
			File:        f.File,
			Message:     f.Message,
		})
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// Match сообщает, есть ли находка в baseline.
func (b *Baseline) Match(f sarif.Finding) bool {
	if b == nil {
		return false
	}
	want := findingKey(f)
	for _, e := range b.Findings {
		if e.key() == want {
			return true
		}
	}
	return false
}
