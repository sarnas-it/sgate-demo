// Package quality измеряет качество статического анализа на квалификационном
// наборе тестов по ГОСТ Р 71207-2024: формула (1) — доля ложноположительных
// срабатываний 100·FPW/TW (10.4), формула (2) — доля пропусков 100·FN/TB (10.5).
package quality

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"code.sarnas.ru/sgate/internal/gost"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Defect — известная ошибка в тестовой программе (10.3): размещение и тип.
type Defect struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Type string `json:"type"`
	CWE  string `json:"cwe,omitempty"`
	Note string `json:"note,omitempty"`
}

// Manifest — описание квалификационного набора: известные ошибки и файлы,
// на которых анализатор не должен выдавать ни одного предупреждения
// (тесты 10.2 б).
type Manifest struct {
	Version   int      `json:"version"`
	Tolerance int      `json:"tolerance"`
	Clean     []string `json:"clean"`
	Defects   []Defect `json:"defects"`
}

// LoadManifest читает описание набора.
func LoadManifest(path string) (Manifest, error) {
	m := Manifest{Version: 1, Tolerance: 2}
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, fmt.Errorf("read manifest: %w", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Version != 1 {
		return m, fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if m.Tolerance <= 0 {
		m.Tolerance = 2
	}
	return m, nil
}

// TypeMetrics — показатели по одному типу 6.3.
type TypeMetrics struct {
	Type   string  `json:"type"`
	TB     int     `json:"tb"`
	TP     int     `json:"tp"`
	FN     int     `json:"fn"`
	FP     int     `json:"fp"`
	TW     int     `json:"tw"`
	FNRate float64 `json:"fn_rate"`
	FPRate float64 `json:"fp_rate"`
}

// Metrics — результат измерения по 8.4.
type Metrics struct {
	TB       int                    `json:"tb"`
	TP       int                    `json:"tp"`
	FN       int                    `json:"fn"`
	FP       int                    `json:"fp"`
	TW       int                    `json:"tw"`
	FNRate   float64                `json:"fn_rate"`
	FPRate   float64                `json:"fp_rate"`
	Skipped  int                    `json:"skipped_non_critical"`
	Passed   bool                   `json:"passed"`
	ByType   map[string]TypeMetrics `json:"by_type"`
	Missed   []Defect               `json:"missed"`
	FalsePos []sarif.Finding        `json:"false_positives"`
}

// Measure сопоставляет находки с описанием ошибок. Находка засчитывается как
// обнаружение, если она в том же файле, в пределах допуска по строке и её тип
// по 6.3 совпадает с типом ожидаемой ошибки (если тип известен).
func Measure(m Manifest, findings []sarif.Finding) Metrics {
	res := Metrics{ByType: map[string]TypeMetrics{}}
	res.TB = len(m.Defects)
	clean := map[string]bool{}
	for _, f := range m.Clean {
		clean[f] = true
	}

	matched := make([]bool, len(m.Defects))
	fpFlags := make([]bool, len(findings))
	for i, f := range findings {
		// 8.4 относится к критическим типам 6.3: предупреждения других
		// типов (качество кода, стиль) в показателях не участвуют.
		if f.GOSTType == "" {
			res.Skipped++
			continue
		}
		res.TW++
		hit := -1
		// Первый проход: тот же файл, тип и строка в пределах допуска.
		for j, d := range m.Defects {
			if matched[j] || f.File != d.File {
				continue
			}
			if abs(f.Line-d.Line) > m.Tolerance {
				continue
			}
			if d.Type != "" && f.GOSTType != d.Type {
				continue
			}
			hit = j
			break
		}
		// Второй проход: тот же файл и тип, но другая строка. Дубли одного
		// дефекта разными правилами (импорт + вызов) не считаются ложными.
		if hit < 0 {
			for j, d := range m.Defects {
				if f.File == d.File && (d.Type == "" || f.GOSTType == d.Type) {
					hit = j
					break
				}
			}
		}
		if hit >= 0 && !clean[f.File] {
			matched[hit] = true
			continue
		}
		// Предупреждение на «чистом» файле — ложное: тесты 10.2 б
		// требуют нуля ложных срабатываний на них.
		fpFlags[i] = true
		res.FalsePos = append(res.FalsePos, f)
	}

	for j, d := range m.Defects {
		tm := res.ByType[d.Type]
		tm.Type = d.Type
		tm.TB++
		if matched[j] {
			tm.TP++
		} else {
			tm.FN++
			res.Missed = append(res.Missed, d)
		}
		res.ByType[d.Type] = tm
	}
	res.TP = res.TB - len(res.Missed)
	res.FN = len(res.Missed)
	res.FP = len(res.FalsePos)
	res.FNRate = rate(res.FN, res.TB)
	res.FPRate = rate(res.FP, res.TW)

	// Показатели по типам: TW типа — все предупреждения, у которых тип
	// совпадает (для FP) плюс найденные ошибки этого типа.
	for i, f := range findings {
		t := f.GOSTType
		if t == "" {
			t = "не классифицировано"
		}
		tm := res.ByType[t]
		tm.Type = t
		if f.GOSTType == "" {
			continue
		}
		tm.TW++
		if fpFlags[i] {
			tm.FP++
		}
		res.ByType[t] = tm
	}
	for t, tm := range res.ByType {
		tm.FNRate = rate(tm.FN, tm.TB)
		tm.FPRate = rate(tm.FP, tm.TW)
		res.ByType[t] = tm
	}
	// 8.4: не более 50 % ложноположительных и не более 50 % пропусков.
	res.Passed = res.FPRate <= 50 && res.FNRate <= 50
	return res
}

func rate(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(part) / float64(total)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// Markdown собирает отчёт о качестве для передачи в комплект документов.
func (m Metrics) Markdown(title string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	b.WriteString("Методика: ГОСТ Р 71207-2024, п. 10.4 — формула (1) 100·FPW/TW,\n")
	b.WriteString("п. 10.5 — формула (2) 100·FN/TB. Порог по 8.4: не более 50 % по обоим показателям.\n\n")
	b.WriteString("| Показатель | Значение |\n|---|---|\n")
	fmt.Fprintf(&b, "| Ошибок в наборе (TB) | %d |\n", m.TB)
	fmt.Fprintf(&b, "| Обнаружено (TP) | %d |\n", m.TP)
	fmt.Fprintf(&b, "| Пропущено (FN) | %d |\n", m.FN)
	fmt.Fprintf(&b, "| Всего предупреждений критических типов (TW) | %d |\n", m.TW)
	fmt.Fprintf(&b, "| Предупреждений не критических типов (вне 8.4) | %d |\n", m.Skipped)
	fmt.Fprintf(&b, "| Ложных (FPW) | %d |\n", m.FP)
	fmt.Fprintf(&b, "| Доля ложноположительных (1) | %.1f %% |\n", m.FPRate)
	fmt.Fprintf(&b, "| Доля пропусков (2) | %.1f %% |\n", m.FNRate)
	verdict := "ПРОЙДЕНО"
	if !m.Passed {
		verdict = "НЕ ПРОЙДЕНО"
	}
	fmt.Fprintf(&b, "| Порог 8.4 | %s |\n\n", verdict)

	b.WriteString("## По типам ошибок (6.3)\n\n")
	b.WriteString("| Тип | Ошибок | Найдено | Пропущено | Предупреждений | FP, % | FN, % |\n|---|---|---|---|---|---|---|\n")
	var types []string
	for t := range m.ByType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		tm := m.ByType[t]
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %.1f | %.1f |\n",
			t, tm.TB, tm.TP, tm.FN, tm.TW, tm.FPRate, tm.FNRate)
	}

	if len(m.Missed) > 0 {
		b.WriteString("\n## Пропущенные ошибки\n\n")
		for _, d := range m.Missed {
			fmt.Fprintf(&b, "- `%s:%d` — %s, %s\n", d.File, d.Line, d.Type, d.Note)
		}
	}
	if len(m.FalsePos) > 0 {
		b.WriteString("\n## Ложные срабатывания\n\n")
		for _, f := range m.FalsePos {
			fmt.Fprintf(&b, "- `%s:%d` — %s %s (%s)\n", f.File, f.Line, f.Analyzer, f.RuleID, f.GOSTType)
		}
	}
	if len(m.Missed) == 0 && len(m.FalsePos) == 0 {
		b.WriteString("\nПропусков и ложных срабатываний на наборе нет.\n")
	}
	return b.String()
}

// DescribeType возвращает человекочитаемое имя типа 6.3.
func DescribeType(code string) string {
	for _, t := range gost.Catalog() {
		if string(t.Code) == code {
			return t.Name
		}
	}
	return code
}
