// Command ast — AST-анализатор SGATE как отдельный модуль.
//
// Контракт анализатора (тот же для любого языка):
//
//	SGATE_REPO  — корень репозитория (или -repo)
//	SGATE_OUT   — путь к SARIF-отчёту (или -out)
//
// Пишет SARIF 2.1.0, печатает прогресс «ast-scanned: <файл>» (по нему
// покрытие SGATE отличает «чисто» от «не просканировано»), код возврата 0 —
// прогон состоялся, 2 — внутренняя ошибка. Находки не влияют на код возврата:
// политика (block high и т.п.) — дело SGATE, а не анализатора.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"code.sarnas.ru/sgate/analyzers/ast/internal/rules"
	"code.sarnas.ru/sgate/analyzers/ast/internal/sarif"
)

func main() {
	repo := os.Getenv("SGATE_REPO")
	out := os.Getenv("SGATE_OUT")
	quiet := false
	flag.StringVar(&repo, "repo", repo, "корень репозитория (по умолчанию SGATE_REPO)")
	flag.StringVar(&out, "out", out, "путь к SARIF (по умолчанию SGATE_OUT)")
	flag.BoolVar(&quiet, "quiet", false, "не печатать прогресс по файлам")
	flag.Parse()

	if repo == "" || out == "" {
		fmt.Fprintln(os.Stderr, "ast: нужны SGATE_REPO и SGATE_OUT (или -repo/-out)")
		os.Exit(2)
	}
	if _, err := os.Stat(repo); err != nil {
		fmt.Fprintf(os.Stderr, "ast: репозиторий недоступен: %v\n", err)
		os.Exit(2)
	}

	findings, scanned, err := rules.Analyze(repo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ast: анализ: %v\n", err)
		os.Exit(2)
	}
	if !quiet {
		for _, f := range scanned {
			fmt.Fprintf(os.Stderr, "ast-scanned: %s\n", f)
		}
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "ast: каталог отчёта: %v\n", err)
		os.Exit(2)
	}
	if err := sarif.Write(out, findings); err != nil {
		fmt.Fprintf(os.Stderr, "ast: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "ast: файлов %d, находок %d, отчёт %s\n", len(scanned), len(findings), out)
}
