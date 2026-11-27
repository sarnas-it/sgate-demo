package analysis

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestIndirectCallTaint — поток «ввод → func-значение в структуре → SQL»
// должен находиться: именно этот случай AST-модули пропускают (7.4).
func TestIndirectCallTaint(t *testing.T) {
	findings, scanned, err := Analyze(filepath.Join("..", "..", "testdata", "indirect"))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(scanned) == 0 {
		t.Fatal("не просканировано ни одного файла")
	}
	var sql []Finding
	for _, f := range findings {
		if f.Rule == "sgate-ssa-taint-sql" {
			sql = append(sql, f)
		}
	}
	if len(sql) != 1 {
		t.Fatalf("ожидалась 1 SQL-находка, получено %d: %+v", len(sql), findings)
	}
	if got := sql[0].File; got != "main.go" {
		t.Errorf("файл находки = %q, ожидался main.go", got)
	}
	// Строка db.Exec внутри exec, а не вызов через структуру: отчёт должен
	// указывать на сток, а не на источник.
	if sql[0].Line != 22 {
		t.Errorf("строка находки = %d, ожидалась 22 (db.Exec в exec)", sql[0].Line)
	}
}

// TestNoFindingsWithoutSource — без источника пользовательских данных
// параметр функции не заражается и SQL не помечается.
func TestNoFindingsWithoutSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/clean\n\ngo 1.26.0\n")
	writeFile(t, dir, "main.go", `package main

import "database/sql"

func run(db *sql.DB, in string) {
	_, _ = db.Exec(in)
}

func main() {}
`)
	findings, _, err := Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("ожидалось 0 находок, получено %+v", findings)
	}
}

// TestCatalogUnique — идентификаторы правил уникальны и с CWE.
func TestCatalogUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Catalog() {
		if seen[r.ID] {
			t.Fatalf("дубликат правила %q", r.ID)
		}
		seen[r.ID] = true
		if !strings.HasPrefix(r.CWE, "CWE-") || r.Severity == "" || r.Message == "" {
			t.Errorf("правило %q заполнено не полностью: %+v", r.ID, r)
		}
	}
}

// TestNoSSRFFromHeaderLookup — регрессия: r.Header.Get — это map-лукап, а не
// исходящий HTTP-запрос. Раньше он попадал в правило SSRF и давал FP на
// каждом чтении заголовка; контекст, переданный в NewRequestWithContext, тоже
// не должен считаться URL.
func TestNoSSRFFromHeaderLookup(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/hdr\n\ngo 1.26.0\n")
	writeFile(t, dir, "main.go", `package main

import (
	"net/http"
	"time"
)

const auditURL = "https://audit.internal/events"

func handler(w http.ResponseWriter, r *http.Request) {
	if id := r.Header.Get("X-User-ID"); id != "" {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, auditURL, nil)
		if err == nil {
			_, _ = http.DefaultClient.Do(req)
		}
	}
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":0", nil)
	time.Sleep(0)
}
`)
	findings, _, err := Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range findings {
		if f.Rule == "sgate-ssa-taint-ssrf" {
			t.Fatalf("ложный SSRF на Header.Get/фиксированном URL: %+v", f)
		}
	}
}
