// Package gost реализует требования ГОСТ Р 71207-2024 к результатам
// статического анализа: тип критической ошибки (6.3), описание (8.5 б),
// соответствие CWE (8.10) и матрицу покрытия типов (7.3).
package gost

import (
	"fmt"
	"sort"
	"strings"

	"code.sarnas.ru/sgate/internal/sarif"
)

// Type — код типа критической ошибки по 6.3.
type Type string

const (
	// Taint — 6.3 а) непроверенное использование чувствительных данных.
	Taint Type = "6.3а"
	// Overflow — 6.3 б) целочисленное переполнение и знаковость.
	Overflow Type = "6.3б"
	// Bounds — 6.3 в) выход за границы буфера.
	Bounds Type = "6.3в"
	// SecMisuse — 6.3 г) неправильное использование средств ИБ
	// (криптография, разграничение доступа, права доступа).
	SecMisuse Type = "6.3г"
	// Concurrency — 6.3 д) многопоточные примитивы. Для компилируемых языков
	// 7.3 этот тип не требует обязательного покрытия.
	Concurrency Type = "6.3д"
)

// TypeInfo — описание типа ошибки по 8.10: описание, причины,
// пример ошибочного кода и рекомендация по исправлению.
type TypeInfo struct {
	Code     Type
	Name     string
	Desc     string
	Causes   []string
	BadCode  string
	Fix      string
	CWE      []string
	Required bool // обязателен ли тип для компилируемых языков по 7.3
}

// Catalog возвращает типы ошибок в порядке 6.3.
func Catalog() []TypeInfo {
	return []TypeInfo{
		{
			Code:     Taint,
			Name:     "Непроверенное использование чувствительных данных",
			Desc:     "Данные из недоверенного источника (ввод пользователя, файл, сеть, переменная окружения) попадают в опасный сток без проверки: SQL-запрос, команда ОС, путь к файлу, HTTP-запрос, HTML-вывод.",
			Causes:   []string{"конкатенация ввода в запрос", "использование ввода как пути", "вывод без экранирования", "запрос по URL из ввода"},
			BadCode:  "query := \"SELECT * FROM users WHERE name = '\" + r.URL.Query().Get(\"name\") + \"'\"",
			Fix:      "Параметризованный запрос, whitelist путей, экранирование вывода, проверка схемы и хоста URL.",
			CWE:      []string{"CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-918"},
			Required: true,
		},
		{
			Code:     Overflow,
			Name:     "Целочисленное переполнение и смешение знаковости",
			Desc:     "Преобразование или арифметика приводят к переполнению либо к неверной интерпретации знаковых и беззнаковых значений.",
			Causes:   []string{"сужение разрядности (int64 → int32)", "int ↔ uint без проверки", "переполнение при умножении/сложении"},
			BadCode:  "size := int(uint64(n) << 40)",
			Fix:      "Проверка диапазона перед преобразованием, использование беззнаковой арифметики осознанно, safe-conversion хелперы.",
			CWE:      []string{"CWE-190", "CWE-191", "CWE-681"},
			Required: true,
		},
		{
			Code:     Bounds,
			Name:     "Выход за границы буфера",
			Desc:     "Чтение или запись за пределами выделенной области памяти; в Go проявляется как обращение к срезу по индексу без проверки границ.",
			Causes:   []string{"индекс из внешних данных", "срез без проверки длины", "неверный расчёт размера"},
			BadCode:  "v := items[r.URL.Query().Get(\"i\")]",
			Fix:      "Проверка индекса и длины перед доступом, срезы с ограничением, безопасные итераторы.",
			CWE:      []string{"CWE-125", "CWE-787"},
			Required: true,
		},
		{
			Code:     SecMisuse,
			Name:     "Некорректное использование средств защиты информации",
			Desc:     "Слабая криптография, отключённая проверка TLS, предсказуемый генератор случайных чисел, небезопасные права доступа, секреты в коде.",
			Causes:   []string{"MD5/SHA1/DES/RC4", "InsecureSkipVerify", "math/rand для токенов", "права 0777/0666", "пароль в коде"},
			BadCode:  "h := md5.Sum([]byte(password))",
			Fix:      "SHA-256/argon2, проверка сертификата, crypto/rand, права 0750/0600, секреты из хранилища.",
			CWE:      []string{"CWE-327", "CWE-295", "CWE-338", "CWE-276", "CWE-798"},
			Required: true,
		},
		{
			Code:     Concurrency,
			Name:     "Ошибки работы с многопоточными примитивами",
			Desc:     "Гонки данных, неверная синхронизация, потеря сигнала при работе с потоками и примитивами синхронизации.",
			Causes:   []string{"общий доступ без блокировки", "потерянное пробуждение", "захват мьютекса по значению"},
			BadCode:  "var mu sync.Mutex; go func() { defer mu.Unlock() }()",
			Fix:      "Модель памяти языка, race detector, sync-примитивы по указателю, каналы вместо общего состояния.",
			CWE:      []string{"CWE-362", "CWE-833"},
			Required: false, // 7.3 исключает перечисление д) для компилируемых языков
		},
	}
}

// RuleInfo — сведения о правиле анализатора: тип по 6.3, CWE и краткое описание.
type RuleInfo struct {
	RuleID   string
	Analyzer string
	Type     Type
	CWE      []string
	Summary  string
}

// gosecRules — сопоставление правил gosec типам 6.3 и CWE.
// Правила вне таблицы считаются неклассифицированными (не ИБ-типы:
// качество кода, стиль, необработанные ошибки).
var gosecRules = map[string]RuleInfo{
	"G101": {Type: SecMisuse, CWE: []string{"CWE-798"}, Summary: "Захардкоженные учётные данные"},
	"G102": {Type: SecMisuse, CWE: []string{"CWE-200"}, Summary: "Привязка к интерфейсу 0.0.0.0"},
	"G106": {Type: SecMisuse, CWE: []string{"CWE-322"}, Summary: "SSH без проверки ключа хоста"},
	"G107": {Type: Taint, CWE: []string{"CWE-918"}, Summary: "URL из недоверенного источника в HTTP-запросе"},
	"G111": {Type: Taint, CWE: []string{"CWE-22"}, Summary: "Обход каталога через http.Dir"},
	"G115": {Type: Overflow, CWE: []string{"CWE-190"}, Summary: "Переполнение при преобразовании целых чисел"},
	"G201": {Type: Taint, CWE: []string{"CWE-89"}, Summary: "SQL-запрос через форматную строку"},
	"G202": {Type: Taint, CWE: []string{"CWE-89"}, Summary: "SQL-запрос через конкатенацию"},
	"G203": {Type: Taint, CWE: []string{"CWE-79"}, Summary: "Неэкранированные данные в HTML-шаблоне"},
	"G204": {Type: Taint, CWE: []string{"CWE-78"}, Summary: "Запуск процесса с параметрами из переменной"},
	"G301": {Type: SecMisuse, CWE: []string{"CWE-276"}, Summary: "Права каталога шире 0750"},
	"G302": {Type: SecMisuse, CWE: []string{"CWE-276"}, Summary: "Права файла при chmod шире 0600"},
	"G303": {Type: SecMisuse, CWE: []string{"CWE-377"}, Summary: "Файл с предсказуемым именем"},
	"G304": {Type: Taint, CWE: []string{"CWE-22"}, Summary: "Путь к файлу из недоверенного источника"},
	"G305": {Type: Taint, CWE: []string{"CWE-22"}, Summary: "Обход пути при распаковке архива"},
	"G306": {Type: SecMisuse, CWE: []string{"CWE-276"}, Summary: "Права файла при записи шире 0600"},
	"G401": {Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Слабая криптография (DES/RC4/MD5/SHA1)"},
	"G402": {Type: SecMisuse, CWE: []string{"CWE-295"}, Summary: "Небезопасные настройки TLS"},
	"G403": {Type: SecMisuse, CWE: []string{"CWE-326"}, Summary: "Слишком короткий ключ RSA"},
	"G404": {Type: SecMisuse, CWE: []string{"CWE-338"}, Summary: "math/rand для чувствительных значений"},
	"G405": {Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Блочный шифр с неверным режимом"},
	"G406": {Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Устаревший примитив шифрования"},
	"G501": {Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Импорт crypto/md5"},
	"G502": {Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Импорт crypto/des"},
	"G503": {Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Импорт crypto/rc4"},
	"G505": {Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Импорт crypto/sha1"},
	"G602": {Type: Bounds, CWE: []string{"CWE-125"}, Summary: "Доступ к срезу за границами"},
	"G701": {Type: Taint, CWE: []string{"CWE-89"}, Summary: "SQL-инъекция"},
	"G702": {Type: Taint, CWE: []string{"CWE-78"}, Summary: "Инъекция команды ОС"},
	"G703": {Type: Taint, CWE: []string{"CWE-22"}, Summary: "Обход пути (path traversal)"},
	"G704": {Type: Taint, CWE: []string{"CWE-918"}, Summary: "SSRF"},
	"G705": {Type: Taint, CWE: []string{"CWE-79"}, Summary: "XSS"},
	"G706": {Type: Taint, CWE: []string{"CWE-117"}, Summary: "Инъекция в журнал"},
}

// semgrepHints связывают фрагменты идентификаторов правил Semgrep с типами 6.3.
// Порядок важен: более specific проверки идут первыми.
var semgrepHints = []struct {
	fragment string
	info     RuleInfo
}{
	{"slice-index", RuleInfo{Type: Bounds, CWE: []string{"CWE-125"}, Summary: "Индекс среза из ввода"}},
	{"out-of-bounds", RuleInfo{Type: Bounds, CWE: []string{"CWE-125"}, Summary: "Выход за границы"}},
	{"hardcoded-credentials", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-798"}, Summary: "Захардкоженные учётные данные"}},
	{"sql", RuleInfo{Type: Taint, CWE: []string{"CWE-89"}, Summary: "SQL-инъекция"}},
	{"command-injection", RuleInfo{Type: Taint, CWE: []string{"CWE-78"}, Summary: "Инъекция команды"}},
	{"shell", RuleInfo{Type: Taint, CWE: []string{"CWE-78"}, Summary: "Вызов оболочки с данными"}},
	{"xss", RuleInfo{Type: Taint, CWE: []string{"CWE-79"}, Summary: "XSS"}},
	{"raw-html", RuleInfo{Type: Taint, CWE: []string{"CWE-79"}, Summary: "HTML без экранирования"}},
	{"dangerouslysetinnerhtml", RuleInfo{Type: Taint, CWE: []string{"CWE-79"}, Summary: "dangerouslySetInnerHTML"}},
	{"path-traversal", RuleInfo{Type: Taint, CWE: []string{"CWE-22"}, Summary: "Обход пути"}},
	{"ssrf", RuleInfo{Type: Taint, CWE: []string{"CWE-918"}, Summary: "SSRF"}},
	{"open-redirect", RuleInfo{Type: Taint, CWE: []string{"CWE-601"}, Summary: "Открытый редирект"}},
	{"overflow", RuleInfo{Type: Overflow, CWE: []string{"CWE-190"}, Summary: "Целочисленное переполнение"}},
	{"sha1", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "SHA1"}},
	{"md5", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "MD5"}},
	{"weak-crypto", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-327"}, Summary: "Слабая криптография"}},
	{"math-random", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-338"}, Summary: "math/rand"}},
	{"insecure-random", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-338"}, Summary: "Предсказуемый генератор"}},
	{"use-tls", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-319"}, Summary: "HTTP без TLS"}},
	{"tls", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-295"}, Summary: "Настройки TLS"}},
	{"permission", RuleInfo{Type: SecMisuse, CWE: []string{"CWE-276"}, Summary: "Права доступа"}},
}

// Lookup возвращает сведения о правиле. Для gosec — по таблице, для Semgrep —
// по фрагменту идентификатора правила.
func Lookup(analyzer, ruleID string) (RuleInfo, bool) {
	if analyzer == "gosec" {
		if info, ok := gosecRules[ruleID]; ok {
			info.RuleID, info.Analyzer = ruleID, analyzer
			return info, true
		}
		return RuleInfo{}, false
	}
	low := strings.ToLower(ruleID)
	for _, h := range semgrepHints {
		if strings.Contains(low, h.fragment) {
			info := h.info
			info.RuleID, info.Analyzer = ruleID, analyzer
			return info, true
		}
	}
	return RuleInfo{}, false
}

// Classify возвращает код типа 6.3 или пустую строку, если правило
// не относится к критическим типам стандарта.
func Classify(analyzer, ruleID string) Type {
	if info, ok := Lookup(analyzer, ruleID); ok {
		return info.Type
	}
	return ""
}

// Assign проставляет находке тип по 6.3, CWE и описание — требования 8.5 б), в).
func Assign(f *sarif.Finding) {
	info, ok := Lookup(f.Analyzer, f.RuleID)
	if !ok {
		return
	}
	f.GOSTType = string(info.Type)
	if len(info.CWE) > 0 && f.CWE == "" {
		f.CWE = info.CWE[0]
	}
	if f.Description == "" {
		f.Description = info.Summary
	}
}

// CoverageRow — строка матрицы покрытия: тип 6.3 и правила, которые его находят.
type CoverageRow struct {
	Type     Type
	Name     string
	Required bool
	Analyzer string
	Rules    []string
}

// Coverage строит матрицу покрытия типов 6.3 по таблице правил.
func Coverage() []CoverageRow {
	byType := map[Type]map[string][]string{}
	add := func(info RuleInfo) {
		if byType[info.Type] == nil {
			byType[info.Type] = map[string][]string{}
		}
		byType[info.Type][info.Analyzer] = append(byType[info.Type][info.Analyzer], info.RuleID)
	}
	for id, info := range gosecRules {
		info.RuleID, info.Analyzer = id, "gosec"
		add(info)
	}
	for _, h := range semgrepHints {
		info := h.info
		info.RuleID, info.Analyzer = "semgrep:"+h.fragment, "semgrep"
		add(info)
	}
	var rows []CoverageRow
	for _, t := range Catalog() {
		row := CoverageRow{Type: t.Code, Name: t.Name, Required: t.Required}
		for analyzer, rules := range byType[t.Code] {
			sort.Strings(rules)
			row.Analyzer = strings.TrimSpace(row.Analyzer + " " + analyzer)
			row.Rules = append(row.Rules, rules...)
		}
		sort.Strings(row.Rules)
		rows = append(rows, row)
	}
	return rows
}

// CatalogMarkdown собирает документ описания типов ошибок по 8.10.
func CatalogMarkdown() string {
	var b strings.Builder
	b.WriteString("# Типы ошибок SGATE по ГОСТ Р 71207-2024 (п. 8.10)\n\n")
	b.WriteString("Документ генерируется командой `sgate catalog` из таблицы правил:\n")
	b.WriteString("описание типа (6.3), причины, пример ошибочного кода, рекомендация\n")
	b.WriteString("по исправлению и соответствие CWE.\n\n")
	for _, t := range Catalog() {
		fmt.Fprintf(&b, "## %s. %s\n\n", t.Code, t.Name)
		fmt.Fprintf(&b, "%s\n\n", t.Desc)
		b.WriteString("**Возможные причины**\n\n")
		for _, c := range t.Causes {
			fmt.Fprintf(&b, "- %s\n", c)
		}
		b.WriteString("\n**Пример ошибочного кода**\n\n```go\n")
		b.WriteString(t.BadCode + "\n```\n\n")
		fmt.Fprintf(&b, "**Как исправлять.** %s\n\n", t.Fix)
		fmt.Fprintf(&b, "**CWE:** %s\n\n", strings.Join(t.CWE, ", "))
		if t.Required {
			b.WriteString("**Обязателен для компилируемых языков (7.3):** да\n\n")
		} else {
			b.WriteString("**Обязателен для компилируемых языков (7.3):** нет, исключён перечислением д)\n\n")
		}
	}
	b.WriteString("## Матрица покрытия (7.3)\n\n")
	b.WriteString("| Тип | Обязателен | Анализаторы | Правила |\n|---|---|---|---|\n")
	for _, row := range Coverage() {
		req := "нет"
		if row.Required {
			req = "да"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", row.Type, req, row.Analyzer, strings.Join(row.Rules, ", "))
	}
	return b.String()
}
