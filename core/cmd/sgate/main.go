// sgate — прототип платформы анализаторов SGATE.
package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"code.sarnas.ru/sgate/internal/analyzer"
	"code.sarnas.ru/sgate/internal/baseline"
	"code.sarnas.ru/sgate/internal/config"
	"code.sarnas.ru/sgate/internal/detect"
	"code.sarnas.ru/sgate/internal/policy"
	"code.sarnas.ru/sgate/internal/sarif"
)

func main() {
	repo := flag.String("repo", ".", "путь к репозиторию")
	cfgPath := flag.String("config", "analyzers.yaml", "путь к analyzers.yaml")
	format := flag.String("format", "text", "text, json или sarif")
	block := flag.String("block", "high", "порог блокировки: critical|high|medium|low")
	list := flag.Bool("list", false, "показать анализаторы и выйти")
	keep := flag.Bool("keep", false, "не удалять временные SARIF")
	verbose := flag.Bool("v", false, "печатать выбранные анализаторы")
	baselinePath := flag.String("baseline", "", "файл принятых находок")
	writeBaseline := flag.String("write-baseline", "", "записать текущие находки как принятые")
	baseRef := flag.String("base", "", "базовая ревизия для diff-only")
	headRef := flag.String("head", "HEAD", "ревизия для diff-only")
	cacheDir := flag.String("cache-dir", ".sgate-cache", "каталог кэша анализаторов")
	noCache := flag.Bool("no-cache", false, "не использовать кэш")
	flag.Parse()

	code, err := run(*repo, *cfgPath, *format, *block, *list, *keep, *verbose, *baselinePath, *writeBaseline, *baseRef, *headRef, *cacheDir, *noCache)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sgate:", err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}

func filterExcluded(findings []sarif.Finding, patterns []string) []sarif.Finding {
	if len(patterns) == 0 {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if !isExcluded(f.File, patterns) {
			out = append(out, f)
		}
	}
	return out
}

func isExcluded(file string, patterns []string) bool {
	file = filepath.ToSlash(file)
	for _, p := range patterns {
		p = strings.TrimSpace(filepath.ToSlash(p))
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/**") {
			if strings.HasPrefix(file, strings.TrimSuffix(p, "/**")+"/") {
				return true
			}
			continue
		}
		if ok, _ := path.Match(p, file); ok {
			return true
		}
	}
	return false
}

func repoCommit(repo string) (string, bool) {
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", false
	}
	status, err := exec.Command("git", "-C", repo, "status", "--porcelain").Output()
	if err != nil || len(strings.TrimSpace(string(status))) > 0 {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func cacheKey(spec config.Analyzer, commit string) string {
	raw, _ := json.Marshal(spec)
	sum := sha1.Sum(append(raw, []byte(commit)...))
	return hex.EncodeToString(sum[:])
}

func changedFiles(repo, base, head string) (map[string]bool, error) {
	out, err := exec.Command("git", "-C", repo, "diff", "--name-only", base+"..."+head).Output()
	if err != nil {
		return nil, err
	}
	files := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files[filepath.ToSlash(line)] = true
		}
	}
	return files, nil
}

func filterChanged(findings []sarif.Finding, files map[string]bool) []sarif.Finding {
	out := findings[:0]
	for _, f := range findings {
		if files[filepath.ToSlash(f.File)] {
			out = append(out, f)
		}
	}
	return out
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func countBaseline(findings []sarif.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Baseline {
			n++
		}
	}
	return n
}

func requiresPresent(repo string, requires []string) bool {
	for _, rel := range requires {
		if _, err := os.Stat(filepath.Join(repo, rel)); err != nil {
			return false
		}
	}
	return true
}

func run(repo, cfgPath, format, block string, list, keep, verbose bool, baselinePath, writeBaseline, baseRef, headRef, cacheDir string, noCache bool) (int, error) {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return 2, err
	}
	cfgAbs, err := filepath.Abs(cfgPath)
	if err != nil {
		return 2, err
	}
	cfg, err := config.Load(cfgAbs)
	if err != nil {
		return 2, err
	}
	if list {
		for _, a := range cfg.Analyzers {
			fmt.Printf("%-12s %-8s %s\n", a.ID, a.Runtime, strings.Join(a.Languages, ","))
		}
		return 0, nil
	}

	langs, err := detect.Languages(repoAbs)
	if err != nil {
		return 2, fmt.Errorf("detect languages: %w", err)
	}
	var selected []config.Analyzer
	for _, a := range cfg.Analyzers {
		if !requiresPresent(repoAbs, a.Requires) {
			if verbose {
				fmt.Fprintf(os.Stderr, "sgate: analyzer=%s skipped: missing %v\n", a.ID, a.Requires)
			}
			continue
		}
		for _, l := range a.Languages {
			if langs[strings.ToLower(l)] {
				selected = append(selected, a)
				break
			}
		}
	}
	if len(selected) == 0 {
		fmt.Fprintf(os.Stderr, "sgate: в %s не найдено языков, покрытых анализаторами\n", repoAbs)
		return 0, nil
	}
	if verbose {
		for _, a := range selected {
			fmt.Fprintf(os.Stderr, "sgate: analyzer=%s runtime=%s\n", a.ID, a.Runtime)
		}
	}

	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	configDir := filepath.Dir(cfgAbs)
	commit, clean := repoCommit(repoAbs)
	if noCache {
		cacheDir = ""
	}
	type runResult struct {
		id       string
		findings []sarif.Finding
		err      error
	}
	results := make(chan runResult, len(selected))
	var wg sync.WaitGroup
	for _, spec := range selected {
		wg.Add(1)
		go func(spec config.Analyzer) {
			defer wg.Done()
			key := ""
			if cacheDir != "" && clean {
				key = cacheKey(spec, commit)
				cached := filepath.Join(cacheDir, key+".out")
				if _, err := os.Stat(cached); err == nil {
					got, err := sarif.ParseFile(cached, spec.ID, spec.Format)
					if err == nil {
						results <- runResult{id: spec.ID, findings: got}
						return
					}
				}
			}
			outDir, err := os.MkdirTemp("", "sgate-out-")
			if err != nil {
				results <- runResult{id: spec.ID, err: err}
				return
			}
			if !keep {
				defer os.RemoveAll(outDir)
			}
			path, err := analyzer.Run(context.Background(), spec, repoAbs, configDir, outDir, user)
			if err != nil {
				results <- runResult{id: spec.ID, err: err}
				return
			}
			if key != "" {
				_ = os.MkdirAll(cacheDir, 0o755)
				_ = copyFile(path, filepath.Join(cacheDir, key+".out"))
			}
			got, err := sarif.ParseFile(path, spec.ID, spec.Format)
			if err != nil {
				results <- runResult{id: spec.ID, err: fmt.Errorf("%s: %w", spec.ID, err)}
				return
			}
			results <- runResult{id: spec.ID, findings: got}
		}(spec)
	}
	wg.Wait()
	close(results)

	var findings []sarif.Finding
	var failed []string
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "sgate: %v\n", r.err)
			failed = append(failed, r.id)
			continue
		}
		findings = append(findings, r.findings...)
	}
	if len(failed) == len(selected) {
		return 2, fmt.Errorf("все анализаторы завершились ошибкой: %s", strings.Join(failed, ", "))
	}

	findings = filterExcluded(findings, cfg.Exclude)
	if baseRef != "" {
		if files, err := changedFiles(repoAbs, baseRef, headRef); err == nil {
			findings = filterChanged(findings, files)
		} else if verbose {
			fmt.Fprintf(os.Stderr, "sgate: diff-only пропущен: %v\n", err)
		}
	}
	if baselinePath != "" {
		b, err := baseline.Load(baselinePath)
		if err != nil {
			return 2, err
		}
		for i := range findings {
			findings[i].Baseline = b.Match(findings[i])
		}
	}
	if writeBaseline != "" {
		if err := baseline.Save(writeBaseline, findings); err != nil {
			return 2, fmt.Errorf("write baseline: %w", err)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if policy.Rank(findings[i].Severity) != policy.Rank(findings[j].Severity) {
			return policy.Rank(findings[i].Severity) > policy.Rank(findings[j].Severity)
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	blocking := policy.Blocking(findings, block)

	if format == "sarif" {
		if err := sarif.Write(os.Stdout, findings, "SGATE"); err != nil {
			return 2, err
		}
		fmt.Fprintf(os.Stderr, "итог: %d находок, %d baseline, %d блокирующих, анализаторов %d, ошибок %d\n",
			len(findings), countBaseline(findings), len(blocking), len(selected)-len(failed), len(failed))
	} else if format == "json" {
		payload := map[string]any{
			"findings": findings,
			"summary": map[string]any{
				"total":     len(findings),
				"blocking":  len(blocking),
				"analyzers": len(selected) - len(failed),
				"failed":    failed,
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return 2, err
		}
	} else {
		for _, f := range findings {
			mark := "warn "
			if f.Baseline {
				mark = "base "
			} else if policy.Rank(f.Severity) >= policy.Rank(block) {
				mark = "BLOCK"
			}
			fmt.Printf("[%s] %s:%d %s %s — %s\n", mark, f.File, f.Line, f.Severity, f.RuleID, f.Message)
		}
		fmt.Fprintf(os.Stderr, "итог: %d находок, %d baseline, %d блокирующих, анализаторов %d, ошибок %d\n",
			len(findings), countBaseline(findings), len(blocking), len(selected)-len(failed), len(failed))
	}
	if len(blocking) > 0 {
		return 1, nil
	}
	return 0, nil
}
