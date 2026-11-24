// sgatedast — discovery и запуск DAST-сканеров в согласованном scope.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"code.sarnas.ru/sgate/internal/dast"
	"code.sarnas.ru/sgate/internal/policy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "discover":
		runDiscover(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sgatedast discover|scan [flags]")
}

func runDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	scopePath := fs.String("scope", "dast/scope.example.yaml", "путь к scope")
	out := fs.String("out", "", "записать URL в файл")
	fs.Parse(args)

	scope, err := dast.Load(*scopePath)
	if err != nil {
		fail(err)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	urls, err := dast.Discover(context.Background(), client, scope)
	if err != nil {
		fail(err)
	}
	for _, u := range urls {
		fmt.Println(u)
	}
	fmt.Fprintf(os.Stderr, "найдено целей: %d, scope: %s\n", len(urls), scope.Target)
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fail(err)
		}
		var b []byte
		for _, u := range urls {
			b = append(b, []byte(u+"\n")...)
		}
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fail(err)
		}
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	scopePath := fs.String("scope", "dast/scope.example.yaml", "путь к scope")
	scannersPath := fs.String("scanners", "dast/scanners.yaml", "путь к scanners.yaml")
	id := fs.String("id", "zap-baseline", "id сканера")
	outDir := fs.String("out", "dast/out", "каталог отчётов")
	block := fs.String("block", "high", "порог блокировки")
	confirm := fs.Bool("confirm", false, "подтвердить согласованный стенд")
	fs.Parse(args)

	if !*confirm && os.Getenv("DAST_CONFIRM") != "1" {
		fail(fmt.Errorf("нужно подтверждение: -confirm или DAST_CONFIRM=1"))
	}
	scope, err := dast.Load(*scopePath)
	if err != nil {
		fail(err)
	}
	if !scope.Allowed(scope.Target) {
		fail(fmt.Errorf("target вне scope: %s", scope.Target))
	}
	cfg, err := dast.LoadScanners(*scannersPath)
	if err != nil {
		fail(err)
	}
	var spec *dast.Scanner
	for i := range cfg.Scanners {
		if cfg.Scanners[i].ID == *id {
			spec = &cfg.Scanners[i]
			break
		}
	}
	if spec == nil {
		fail(fmt.Errorf("scanner %q not found", *id))
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fail(err)
	}
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	path, err := spec.Run(context.Background(), scope.Target, *outDir, user)
	if err != nil {
		fail(err)
	}
	findings, err := dast.ParseZAPJSON(path, spec.ID)
	if err != nil {
		fail(err)
	}
	// В отчёт попадают только URL внутри scope.
	filtered := findings[:0]
	for _, f := range findings {
		if scope.Allowed(f.File) {
			filtered = append(filtered, f)
		}
	}
	findings = filtered
	sort.SliceStable(findings, func(i, j int) bool {
		return policy.Rank(findings[i].Severity) > policy.Rank(findings[j].Severity)
	})
	blocking := policy.Blocking(findings, *block)
	for _, f := range findings {
		mark := "warn "
		if policy.Rank(f.Severity) >= policy.Rank(*block) {
			mark = "BLOCK"
		}
		fmt.Printf("[%s] %s %s %s — %s\n", mark, f.File, f.Severity, f.RuleID, f.Message)
	}
	fmt.Fprintf(os.Stderr, "итог DAST: %d находок, %d блокирующих, отчёт: %s\n", len(findings), len(blocking), path)
	if len(blocking) > 0 {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sgatedast:", err)
	os.Exit(2)
}
