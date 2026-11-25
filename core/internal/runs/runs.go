// Package runs хранит результаты запусков анализатора и сравнивает их с
// учётом разметки — требования ГОСТ Р 71207-2024 8.8 и 8.9.
package runs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"code.sarnas.ru/sgate/internal/marking"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Meta — паспорт запуска: чем, когда и на каком коммите получены результаты.
type Meta struct {
	ID         string         `json:"id"`
	Repo       string         `json:"repo"`
	Commit     string         `json:"commit,omitempty"`
	Config     string         `json:"config,omitempty"`
	Started    time.Time      `json:"started"`
	DurationMS int64          `json:"duration_ms"`
	Analyzers  []string       `json:"analyzers"`
	Failed     []string       `json:"failed,omitempty"`
	Total      int            `json:"total"`
	Marking    map[string]int `json:"marking,omitempty"`
	// Coverage — сколько файлов реально открыл каждый анализатор. Нужно,
	// чтобы отличить «чисто» от «анализатор ничего не просканировал»:
	// ГОСТ Р 71207-2024, 8.8 — результаты запуска сохраняются вместе с
	// условиями его выполнения.
	Coverage map[string]int `json:"coverage,omitempty"`
}

// Run — сохранённый результат запуска.
type Run struct {
	Meta     Meta            `json:"meta"`
	Findings []sarif.Finding `json:"findings"`
}

// NewID возвращает идентификатор запуска вида 20261124T205512.
func NewID(t time.Time) string {
	return t.UTC().Format("20060102T150405")
}

// Save записывает запуск в root/<id>/ (findings.json и meta.json)
// и возвращает каталог запуска. Требование 8.8: результаты каждого
// анализа должны сохраняться в хранилище результатов.
func Save(root string, r Run) (string, error) {
	if r.Meta.ID == "" {
		r.Meta.ID = NewID(time.Now())
	}
	dir := filepath.Join(root, r.Meta.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if r.Meta.Marking == nil {
		r.Meta.Marking = map[string]int{}
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), r.Meta); err != nil {
		return "", err
	}
	if err := writeJSON(filepath.Join(dir, "findings.json"), r.Findings); err != nil {
		return "", err
	}
	return dir, nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// Load читает запуск из каталога.
func Load(dir string) (Run, error) {
	var r Run
	raw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return r, fmt.Errorf("read run meta: %w", err)
	}
	if err := json.Unmarshal(raw, &r.Meta); err != nil {
		return r, fmt.Errorf("parse run meta: %w", err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		return r, fmt.Errorf("read run findings: %w", err)
	}
	if err := json.Unmarshal(raw, &r.Findings); err != nil {
		return r, fmt.Errorf("parse run findings: %w", err)
	}
	return r, nil
}

// Latest возвращает каталог последнего запуска в root. "latest" и "-"
// означают то же самое, чтобы команды можно было писать короче.
func Latest(root string) (string, error) {
	if root == "latest" || root == "-" {
		return "", fmt.Errorf("укажите каталог хранилища запусков, а не %q", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read runs: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("в %s нет запусков", root)
	}
	sort.Strings(ids)
	return filepath.Join(root, ids[len(ids)-1]), nil
}

// Diff — сравнение двух запусков по 8.9: предупреждения, присутствующие
// в обоих запусках, только в предыдущем и только в текущем, а также
// скрытые как ложноположительные, размеченные ранее.
type Diff struct {
	Both     []sarif.Finding `json:"both"`
	OnlyPrev []sarif.Finding `json:"only_previous"`
	OnlyCur  []sarif.Finding `json:"only_current"`
	HiddenFP []sarif.Finding `json:"hidden_false_positive"`
	Marked   map[string]int  `json:"marked"`
}

// Compare сопоставляет запуски по ключу разметки (fingerprint), скрывая из
// текущего запуска предупреждения, размеченные как ложные и присутствовавшие
// в сравниваемом запуске (8.9).
func Compare(prev, cur Run, marks *marking.Store) Diff {
	seen := make(map[string]sarif.Finding, len(prev.Findings))
	for _, f := range prev.Findings {
		seen[marking.Key(f)] = f
	}
	d := Diff{Marked: map[string]int{"true": 0, "false": 0, "accepted": 0}}
	inCur := make(map[string]bool, len(cur.Findings))
	for _, f := range cur.Findings {
		key := marking.Key(f)
		inCur[key] = true
		if _, ok := seen[key]; ok {
			d.Both = append(d.Both, f)
			if m, ok := marks.Get(f); ok && m.Category == marking.False {
				d.HiddenFP = append(d.HiddenFP, f)
				d.Marked["false"]++
			}
			continue
		}
		d.OnlyCur = append(d.OnlyCur, f)
	}
	for key, f := range seen {
		if !inCur[key] {
			d.OnlyPrev = append(d.OnlyPrev, f)
		}
	}
	sortFindings(d.Both)
	sortFindings(d.OnlyPrev)
	sortFindings(d.OnlyCur)
	sortFindings(d.HiddenFP)
	return d
}

func sortFindings(fs []sarif.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}
