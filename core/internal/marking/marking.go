// Package marking хранит разметку предупреждений по ГОСТ Р 71207-2024:
// 5.5 требует отнести каждое предупреждение к категории — истинное, ложное
// или истинное без необходимости исправления; 8.6 — автоматизировать
// разметку и связать её с исходным кодом; 8.9 — учитывать разметку при
// сравнении запусков.
package marking

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"code.sarnas.ru/sgate/internal/sarif"
)

// Category — категория разметки по 5.5.
type Category string

const (
	// True — истинное срабатывание: ошибку нужно исправлять.
	True Category = "true"
	// False — ложное срабатывание анализатора.
	False Category = "false"
	// Accepted — истинное, но исправление кода не требуется (принятый риск).
	Accepted Category = "accepted"
)

// Valid сообщает, допустима ли категория.
func (c Category) Valid() bool {
	return c == True || c == False || c == Accepted
}

// Mark — решение по одному предупреждению.
type Mark struct {
	Category  Category  `json:"category"`
	Analyzer  string    `json:"analyzer,omitempty"`
	RuleID    string    `json:"rule_id,omitempty"`
	File      string    `json:"file,omitempty"`
	Line      int       `json:"line,omitempty"`
	GOSTType  string    `json:"gost_type,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store — файл разметки. Ключ — fingerprint находки, поэтому разметка
// переживает сдвиг строк; при отсутствии fingerprint используется
// комбинация анализатор|правило|файл|сообщение.
type Store struct {
	Version int             `json:"version"`
	Marks   map[string]Mark `json:"marks"`
	path    string
}

// Key возвращает ключ разметки для находки.
func Key(f sarif.Finding) string {
	if f.Fingerprint != "" {
		return "fp:" + f.Fingerprint
	}
	return "raw:" + f.Analyzer + "|" + f.RuleID + "|" + f.File + "|" + f.Message
}

// Load читает файл разметки. Отсутствующий файл — пустая разметка:
// разметка не является гейтом и не должна ломать первый запуск.
func Load(path string) (*Store, error) {
	s := &Store{Version: 1, Marks: map[string]Mark{}, path: path}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read markings: %w", err)
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("parse markings: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("unsupported markings version %d", s.Version)
	}
	if s.Marks == nil {
		s.Marks = map[string]Mark{}
	}
	s.path = path
	return s, nil
}

// Save записывает разметку на диск.
func (s *Store) Save() error {
	if s.path == "" {
		return fmt.Errorf("markings: путь не задан")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, append(raw, '\n'), 0o644)
}

// Set фиксирует решение по находке.
func (s *Store) Set(f sarif.Finding, mark Mark) {
	if mark.UpdatedAt.IsZero() {
		mark.UpdatedAt = time.Now().UTC()
	}
	mark.Analyzer = f.Analyzer
	mark.RuleID = f.RuleID
	mark.File = f.File
	mark.Line = f.Line
	mark.GOSTType = f.GOSTType
	s.Marks[Key(f)] = mark
}

// Get возвращает разметку находки.
func (s *Store) Get(f sarif.Finding) (Mark, bool) {
	if s == nil {
		return Mark{}, false
	}
	m, ok := s.Marks[Key(f)]
	return m, ok
}

// Apply проставляет категорию в находки: требование 8.9 — сравнение
// запусков и отчётность должны учитывать выполненную разметку.
func (s *Store) Apply(findings []sarif.Finding) {
	if s == nil {
		return
	}
	for i := range findings {
		if m, ok := s.Get(findings[i]); ok {
			findings[i].Marking = string(m.Category)
		}
	}
}

// Summary считает количество находок по категориям.
func (s *Store) Summary() map[Category]int {
	out := map[Category]int{True: 0, False: 0, Accepted: 0}
	if s == nil {
		return out
	}
	for _, m := range s.Marks {
		out[m.Category]++
	}
	return out
}
