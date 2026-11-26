// Command taint — межпакетный taint-анализатор SGATE отдельным модулем.
//
// Контракт анализатора:
//
//	SGATE_REPO — корень репозитория (или -repo)
//	SGATE_OUT  — путь к SARIF-отчёту (или -out)
//
// Печатает «taint-scanned: <файл>» на каждый разобранный файл; по этому
// маркеру coverage guard отличает «чисто» от «не сканировано».
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"code.sarnas.ru/sgate/analyzers/taint/internal/sarif"
	"code.sarnas.ru/sgate/analyzers/taint/internal/taint"
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
		fmt.Fprintln(os.Stderr, "taint: нужны SGATE_REPO и SGATE_OUT (или -repo/-out)")
		os.Exit(2)
	}
	if _, err := os.Stat(repo); err != nil {
		fmt.Fprintf(os.Stderr, "taint: репозиторий недоступен: %v\n", err)
		os.Exit(2)
	}

	findings, scanned, err := taint.Analyze(repo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taint: анализ: %v\n", err)
		os.Exit(2)
	}
	if !quiet {
		for _, f := range scanned {
			fmt.Fprintf(os.Stderr, "taint-scanned: %s\n", f)
		}
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "taint: каталог отчёта: %v\n", err)
		os.Exit(2)
	}
	if err := sarif.Write(out, findings); err != nil {
		fmt.Fprintf(os.Stderr, "taint: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "taint: файлов %d, находок %d, отчёт %s\n", len(scanned), len(findings), out)
}
