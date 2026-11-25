package gost

import (
	"strings"
	"testing"

	"code.sarnas.ru/sgate/internal/sarif"
)

func TestClassifyCriticalTypes(t *testing.T) {
	cases := []struct {
		analyzer, rule string
		want           Type
	}{
		{"gosec", "G701", Taint},
		{"gosec", "G704", Taint},
		{"gosec", "G115", Overflow},
		{"gosec", "G602", Bounds},
		{"gosec", "G404", SecMisuse},
		{"gosec", "G104", ""},
		{"semgrep", "go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1", SecMisuse},
		{"semgrep", "javascript.express.security.audit.xss.direct-response-write", Taint},
		{"semgrep", "unknown.rule", ""},
	}
	for _, c := range cases {
		if got := Classify(c.analyzer, c.rule); got != c.want {
			t.Errorf("Classify(%s,%s)=%q, want %q", c.analyzer, c.rule, got, c.want)
		}
	}
}

func TestAssignFillsRequirements(t *testing.T) {
	f := sarif.Finding{Analyzer: "gosec", RuleID: "G304"}
	Assign(&f)
	if f.GOSTType != string(Taint) {
		t.Fatalf("GOSTType=%q", f.GOSTType)
	}
	if f.CWE != "CWE-22" {
		t.Fatalf("CWE=%q", f.CWE)
	}
	if f.Description == "" {
		t.Fatal("описание ошибки пустое (8.5 б)")
	}
}

func TestAssignKeepsAnalyzerCWE(t *testing.T) {
	f := sarif.Finding{Analyzer: "gosec", RuleID: "G304", CWE: "CWE-23"}
	Assign(&f)
	if f.CWE != "CWE-23" {
		t.Fatalf("CWE анализатора перезаписан: %q", f.CWE)
	}
}

func TestCoverageCoversRequiredTypes(t *testing.T) {
	covered := map[Type]bool{}
	for _, row := range Coverage() {
		covered[row.Type] = len(row.Rules) > 0
	}
	for _, info := range Catalog() {
		if info.Required && !covered[info.Code] {
			t.Errorf("обязательный тип %s (%s) не покрыт правилами", info.Code, info.Name)
		}
	}
}

func TestCatalogMarkdownHasCWEAandExample(t *testing.T) {
	doc := CatalogMarkdown()
	for _, want := range []string{"6.3а", "CWE-89", "Пример ошибочного кода", "Матрица покрытия"} {
		if !strings.Contains(doc, want) {
			t.Errorf("в каталоге нет %q", want)
		}
	}
}

// TestCoverageIsDeterministic — порядок анализаторов фиксирован, иначе
// документ 8.10 меняется от прогона к прогону и CI-проверка «не устарел»
// падает случайно.
func TestCoverageIsDeterministic(t *testing.T) {
	first := Coverage()
	for i := 0; i < 20; i++ {
		again := Coverage()
		for j := range first {
			if first[j].Analyzer != again[j].Analyzer {
				t.Fatalf("порядок анализаторов нестабилен: %q vs %q", first[j].Analyzer, again[j].Analyzer)
			}
		}
	}
}
