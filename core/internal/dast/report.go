package dast

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"code.sarnas.ru/sgate/internal/policy"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Report — сводка DAST-прогона для ИБ.
type Report struct {
	Target   string
	Date     time.Time
	Scanners []string
	Findings []sarif.Finding
	Blocking int
	Warnings int
	Excepted int
}

// WriteMarkdown пишет отчёт: сводка, находки, покрытие WSTG, ограничения.
func WriteMarkdown(w io.Writer, r Report) error {
	if r.Date.IsZero() {
		r.Date = time.Now()
	}
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "# DAST-отчёт SGATE\n\n")
	fmt.Fprintf(w, "- Цель: `%s`\n", r.Target)
	fmt.Fprintf(w, "- Дата: %s\n", r.Date.Format("2006-01-02 15:04"))
	fmt.Fprintf(w, "- Сканеры: %s\n", strings.Join(r.Scanners, ", "))
	fmt.Fprintf(w, "- Находок: %d, блокирующих: %d, предупреждений: %d, исключений: %d\n\n", len(r.Findings), r.Blocking, r.Warnings, r.Excepted)
	fmt.Fprintf(w, "## Severity\n\n")
	fmt.Fprintf(w, "| Severity | Находок |\n|---|---:|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		fmt.Fprintf(w, "| %s | %d |\n", sev, counts[sev])
	}
	fmt.Fprintf(w, "\n## Находки\n\n")
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "Находок нет.\n\n")
	} else {
		fmt.Fprintf(w, "| Severity | Rule | URL | Что |\n|---|---|---|---|\n")
		findings := append([]sarif.Finding(nil), r.Findings...)
		sort.SliceStable(findings, func(i, j int) bool {
			return policy.Rank(findings[i].Severity) > policy.Rank(findings[j].Severity)
		})
		for _, f := range findings {
			fmt.Fprintf(w, "| %s | `%s` | `%s` | %s |\n", f.Severity, md(f.RuleID), md(f.File), md(f.Message))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "## Покрытие OWASP WSTG\n\n")
	fmt.Fprintf(w, "| Категория | Статус | Что проверено / чего не хватает |\n|---|---|---|\n")
	for _, c := range Coverage(r.Scanners) {
		fmt.Fprintf(w, "| %s | %s | %s |\n", c.Title, c.Status, c.Reason)
	}
	fmt.Fprintf(w, "\n## Ограничения\n\n")
	fmt.Fprintf(w, "- активные проверки только на стенде/по согласованному scope;\n")
	fmt.Fprintf(w, "- baseline не заменяет full scan с аутентификацией;\n")
	fmt.Fprintf(w, "- ложные срабатывания разбираются вручную;\n")
	fmt.Fprintf(w, "- отчёт не является пентестом и не гарантирует отсутствие уязвимостей.\n")
	return nil
}

// WSTGStatus — одна категория WSTG в отчёте.
type WSTGStatus struct {
	Title  string
	Status string
	Reason string
}

// Coverage — честная карта: что даёт текущий набор сканеров, а что нет.
func Coverage(scanners []string) []WSTGStatus {
	has := func(id string) bool {
		for _, s := range scanners {
			if s == id {
				return true
			}
		}
		return false
	}
	// Базовый набор ZAP baseline даёт пассивные проверки; full/auth расширяет.
	status := func(zap, nuclei, ferox bool) string {
		n := 0
		if zap {
			n++
		}
		if nuclei {
			n++
		}
		if ferox {
			n++
		}
		switch {
		case n >= 2:
			return "частично"
		case n == 1:
			return "частично"
		default:
			return "не проверено"
		}
	}
	_ = has
	return []WSTGStatus{
		{"INFO — сбор информации", status(has("zap-baseline") || has("nuclei"), has("nuclei"), has("feroxbuster")), "заголовки, версии, открытые пути; поддомены и облачные хранилища — нет"},
		{"CONF — конфигурация", status(has("zap-baseline"), has("nuclei"), false), "заголовки, TLS, методы; полная конфигурация приложения — частично"},
		{"IDNT — управление идентификацией", "не проверено", "нужны тестовые учётки и сценарии регистрации"},
		{"ATHN — аутентификация", "частично", "ZAP baseline без auth; нужен full scan с тестовыми учётками"},
		{"ATHZ — авторизация", "не проверено", "нужна матрица ролей и проверка IDOR/повышения прав"},
		{"SESS — сессии", "частично", "cookie/заголовки; полный разбор сессий — с auth"},
		{"INPV — валидация ввода", "не проверено", "инъекции требуют активных payload'ов и согласованного стенда"},
		{"ERRH — обработка ошибок", "не проверено", "нужны намеренно сломанные запросы"},
		{"CRYP — криптография", "частично", "TLS и заголовки; padding oracle и свои схемы — вручную"},
		{"BUSL — бизнес-логика", "не проверено", "нужны сценарии и тестовые данные"},
		{"CLNT — клиентская часть", "не проверено", "DOM-XSS, postMessage, WebSocket — нужен браузерный crawl"},
		{"APIT — API", "частично", "ferox/nuclei находят пути; схемы и права — по договору"},
	}
}

func md(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
