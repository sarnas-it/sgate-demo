// sgatedast — discovery и запуск DAST-сканеров в согласованном scope.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"code.sarnas.ru/sgate/internal/dast"
	"code.sarnas.ru/sgate/internal/policy"
	"code.sarnas.ru/sgate/internal/sarif"
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
	case "passive":
		runPassive(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
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

func runPassive(args []string) {
	fs := flag.NewFlagSet("passive", flag.ExitOnError)
	scopePath := fs.String("scope", "dast/scope.example.yaml", "путь к scope")
	out := fs.String("out", "dast/out/passive.json", "JSON-отчёт")
	sarifOut := fs.String("sarif-out", "", "SARIF-отчёт")
	findingsOut := fs.String("findings-out", "", "дописать находки в общий JSONL")
	block := fs.String("block", "high", "порог блокировки")
	fs.Parse(args)

	scope, err := dast.Load(*scopePath)
	if err != nil {
		fail(err)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	findings, err := dast.PassiveScan(context.Background(), client, scope)
	if err != nil {
		fail(err)
	}
	findings = dast.Dedup(findings)
	blocking := policy.Blocking(findings, *block)
	for _, f := range findings {
		mark := "warn "
		if policy.Rank(f.Severity) >= policy.Rank(*block) {
			mark = "BLOCK"
		}
		fmt.Printf("[%s] %s %s %s — %s\n", mark, f.File, f.Severity, f.RuleID, f.Message)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fail(err)
	}
	b, _ := json.MarshalIndent(findings, "", "  ")
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fail(err)
	}
	if *findingsOut != "" {
		if err := dast.AppendFindings(*findingsOut, findings); err != nil {
			fail(err)
		}
	}
	if *sarifOut != "" {
		if err := writeSARIF(*sarifOut, findings); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "SARIF: %s\n", *sarifOut)
	}
	fmt.Fprintf(os.Stderr, "итог passive: %d находок, %d блокирующих, отчёт: %s\n", len(findings), len(blocking), *out)
	if len(blocking) > 0 {
		os.Exit(1)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	scopePath := fs.String("scope", "dast/scope.example.yaml", "путь к scope")
	scannersPath := fs.String("scanners", "dast/scanners.yaml", "путь к scanners.yaml")
	id := fs.String("id", "zap-baseline", "id сканера")
	outDir := fs.String("out", "dast/out", "каталог отчётов")
	block := fs.String("block", "high", "порог блокировки, если нет policy")
	policyPath := fs.String("policy", "", "путь к dast/policy.yaml")
	confirm := fs.Bool("confirm", false, "подтвердить согласованный стенд")
	reportPath := fs.String("report", "", "путь к markdown-отчёту (по умолчанию out/report.md)")
	sarifOut := fs.String("sarif-out", "", "SARIF-отчёт")
	findingsOut := fs.String("findings-out", "", "дописать находки в общий JSONL")
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
	authHeader, err := scope.AuthHeader()
	if err != nil {
		fail(err)
	}
	authValue, err := scope.AuthValue()
	if err != nil {
		fail(err)
	}
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	path, err := spec.Run(context.Background(), scope.Target, filepath.Dir(*scannersPath), *outDir, user, authHeader, authValue)
	if err != nil {
		fail(err)
	}
	var findings []sarif.Finding
	switch spec.Format {
	case "zap-json":
		findings, err = dast.ParseZAPJSON(path, spec.ID)
	case "nuclei-jsonl":
		findings, err = dast.ParseNucleiJSONL(path, spec.ID)
	case "ferox-json":
		findings, err = dast.ParseFeroxJSON(path, spec.ID)
	default:
		err = fmt.Errorf("unsupported scanner format %q", spec.Format)
	}
	if err != nil {
		fail(err)
	}
	findings = dast.Dedup(findings)
	var dastPolicy *dast.Policy
	if *policyPath != "" {
		dastPolicy, err = dast.LoadPolicy(*policyPath)
		if err != nil {
			fail(err)
		}
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
	var blocking, warnings []sarif.Finding
	excepted := 0
	if dastPolicy != nil {
		blocking, warnings, excepted = dastPolicy.Evaluate(findings)
	} else {
		blocking = policy.Blocking(findings, *block)
		for _, f := range findings {
			if policy.Rank(f.Severity) < policy.Rank(*block) {
				warnings = append(warnings, f)
			}
		}
	}
	for _, f := range findings {
		mark := "warn "
		if dastPolicy != nil {
			if dastPolicyBlocking(dastPolicy, f) {
				mark = "BLOCK"
			}
		} else if policy.Rank(f.Severity) >= policy.Rank(*block) {
			mark = "BLOCK"
		}
		fmt.Printf("[%s] %s %s %s — %s\n", mark, f.File, f.Severity, f.RuleID, f.Message)
	}
	report := *reportPath
	if report == "" {
		report = filepath.Join(*outDir, "report.md")
	}
	if f, err := os.Create(report); err == nil {
		_ = dast.WriteMarkdown(f, dast.Report{
			Target: scope.Target, Scanners: []string{spec.ID}, Findings: findings,
			Blocking: len(blocking), Warnings: len(warnings), Excepted: excepted,
		})
		f.Close()
		fmt.Fprintf(os.Stderr, "markdown-отчёт: %s\n", report)
	}
	if *findingsOut != "" {
		if err := dast.AppendFindings(*findingsOut, findings); err != nil {
			fail(err)
		}
	}
	if *sarifOut != "" {
		if err := writeSARIF(*sarifOut, findings); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "SARIF: %s\n", *sarifOut)
	}
	fmt.Fprintf(os.Stderr, "итог DAST: %d находок, %d блокирующих, %d исключений, отчёт: %s\n", len(findings), len(blocking), excepted, path)
	if len(blocking) > 0 {
		os.Exit(1)
	}
}

func dastPolicyBlocking(p *dast.Policy, f sarif.Finding) bool {
	blocking, _, _ := p.Evaluate([]sarif.Finding{f})
	return len(blocking) > 0
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	findingsPath := fs.String("findings", "", "JSONL с находками")
	outDir := fs.String("out", "dast/out", "каталог отчётов")
	target := fs.String("target", "", "цель для отчёта")
	policyPath := fs.String("policy", "", "путь к dast/policy.yaml")
	block := fs.String("block", "high", "порог, если нет policy")
	sarifOut := fs.String("sarif-out", "", "SARIF-отчёт")
	fs.Parse(args)
	if *findingsPath == "" {
		fail(fmt.Errorf("нужен -findings"))
	}
	findings, err := dast.ReadFindings(*findingsPath)
	if err != nil {
		fail(err)
	}
	findings = dast.Dedup(findings)
	var blocking, warnings []sarif.Finding
	excepted := 0
	if *policyPath != "" {
		p, err := dast.LoadPolicy(*policyPath)
		if err != nil {
			fail(err)
		}
		blocking, warnings, excepted = p.Evaluate(findings)
	} else {
		blocking = policy.Blocking(findings, *block)
		for _, f := range findings {
			if policy.Rank(f.Severity) < policy.Rank(*block) {
				warnings = append(warnings, f)
			}
		}
	}
	seen := map[string]bool{}
	var scanners []string
	for _, f := range findings {
		if !seen[f.Analyzer] {
			seen[f.Analyzer] = true
			scanners = append(scanners, f.Analyzer)
		}
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fail(err)
	}
	reportPath := filepath.Join(*outDir, "report.md")
	f, err := os.Create(reportPath)
	if err != nil {
		fail(err)
	}
	if err := dast.WriteMarkdown(f, dast.Report{
		Target: *target, Scanners: scanners, Findings: findings,
		Blocking: len(blocking), Warnings: len(warnings), Excepted: excepted,
	}); err != nil {
		fail(err)
	}
	f.Close()
	if *sarifOut == "" {
		*sarifOut = filepath.Join(*outDir, "report.sarif")
	}
	if err := writeSARIF(*sarifOut, findings); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "сводный отчёт: %s\nSARIF: %s\nитог: %d находок, %d блокирующих, %d исключений\n",
		reportPath, *sarifOut, len(findings), len(blocking), excepted)
	if len(blocking) > 0 {
		os.Exit(1)
	}
}

func writeSARIF(path string, findings []sarif.Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return sarif.Write(f, findings, "SGATE-DAST")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sgatedast:", err)
	os.Exit(2)
}
