package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"code.sarnas.ru/sgate/internal/gost"
	"code.sarnas.ru/sgate/internal/marking"
	"code.sarnas.ru/sgate/internal/quality"
	"code.sarnas.ru/sgate/internal/runs"
	"code.sarnas.ru/sgate/internal/sarif"
)

// runSubcommand обслуживает команды соответствия ГОСТ Р 71207-2024:
// разметку (5.5, 8.6), сравнение запусков (8.9), измерение качества (8.4)
// и документ типов ошибок (8.10). Сканирование осталось в основной команде.
func runSubcommand(args []string) (int, error) {
	switch args[0] {
	case "mark":
		return cmdMark(args[1:])
	case "compare":
		return cmdCompare(args[1:])
	case "quality":
		return cmdQuality(args[1:])
	case "catalog":
		return cmdCatalog(args[1:])
	case "runs":
		return cmdRuns(args[1:])
	default:
		return 2, fmt.Errorf("неизвестная команда %q (mark, compare, quality, catalog, runs)", args[0])
	}
}

// sortFindings упорядочивает находки так же, как основной отчёт: сначала
// критичность, затем файл и строка. Нумерация в `sgate mark -n` опирается на
// этот порядок.
func sortFindings(fs []sarif.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}

func cmdMark(args []string) (int, error) {
	fs := flag.NewFlagSet("mark", flag.ContinueOnError)
	runDir := fs.String("run", "", "каталог запуска (.sgate/runs/<id>)")
	n := fs.Int("n", 0, "номер находки в запуске (1-based, порядок как в отчёте)")
	key := fs.String("key", "", "fingerprint находки вместо номера")
	category := fs.String("category", "", "категория по 5.5: true | false | accepted")
	comment := fs.String("comment", "", "комментарий к решению")
	owner := fs.String("owner", "", "владелец решения (обязателен для accepted)")
	expires := fs.String("expires", "", "срок пересмотра для accepted (YYYY-MM-DD)")
	marksPath := fs.String("markings", ".sgate/markings.json", "файл разметки")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *runDir == "" {
		return 2, fmt.Errorf("укажите -run")
	}
	cat := marking.Category(*category)
	if !cat.Valid() {
		return 2, fmt.Errorf("категория должна быть true, false или accepted")
	}
	if cat == marking.Accepted && (*owner == "" || *expires == "") {
		return 2, fmt.Errorf("для accepted нужны -owner и -expires: принятый риск без владельца и срока не принимается")
	}
	r, err := runs.Load(*runDir)
	if err != nil {
		return 2, err
	}
	sortFindings(r.Findings)
	var target *sarif.Finding
	switch {
	case *key != "":
		for i := range r.Findings {
			if r.Findings[i].Fingerprint == *key {
				target = &r.Findings[i]
				break
			}
		}
		if target == nil {
			return 2, fmt.Errorf("находка с fingerprint %s не найдена", *key)
		}
	case *n > 0:
		if *n > len(r.Findings) {
			return 2, fmt.Errorf("в запуске %d находок, запрошена %d", len(r.Findings), *n)
		}
		target = &r.Findings[*n-1]
	default:
		return 2, fmt.Errorf("укажите -n или -key")
	}

	store, err := marking.Load(*marksPath)
	if err != nil {
		return 2, err
	}
	c := *comment
	if cat == marking.Accepted {
		c = strings.TrimSpace(fmt.Sprintf("%s (до %s)", c, *expires))
	}
	store.Set(*target, marking.Mark{Category: cat, Comment: c, Owner: *owner})
	if err := store.Save(); err != nil {
		return 2, err
	}
	sum := store.Summary()
	fmt.Printf("размечено: %s:%d %s → %s\n", target.File, target.Line, target.RuleID, cat)
	fmt.Printf("итого разметки: true %d, false %d, accepted %d (%s)\n",
		sum[marking.True], sum[marking.False], sum[marking.Accepted], *marksPath)
	return 0, nil
}

func cmdCompare(args []string) (int, error) {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	prev := fs.String("prev", "", "каталог предыдущего запуска (или -1: предпоследний)")
	cur := fs.String("cur", "", "каталог текущего запуска")
	format := fs.String("format", "text", "text | json")
	marksPath := fs.String("markings", ".sgate/markings.json", "файл разметки")
	runsDir := fs.String("runs", ".sgate/runs", "хранилище запусков")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *cur == "" {
		return 2, fmt.Errorf("укажите -cur")
	}
	curRun, err := runs.Load(*cur)
	if err != nil {
		return 2, err
	}
	prevDir := *prev
	if prevDir == "" || prevDir == "-1" {
		prevDir, err = previousRun(*runsDir, *cur)
		if err != nil {
			return 2, err
		}
	}
	prevRun, err := runs.Load(prevDir)
	if err != nil {
		return 2, err
	}
	store, err := marking.Load(*marksPath)
	if err != nil {
		return 2, err
	}
	d := runs.Compare(prevRun, curRun, store)
	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return 0, enc.Encode(d)
	}
	fmt.Printf("сравнение %s → %s\n", prevRun.Meta.ID, curRun.Meta.ID)
	fmt.Printf("в обоих запусках: %d\n", len(d.Both))
	fmt.Printf("только в предыдущем (исправлено/исчезло): %d\n", len(d.OnlyPrev))
	fmt.Printf("только в текущем (новое): %d\n", len(d.OnlyCur))
	fmt.Printf("скрыто как ложноположительные по разметке: %d\n", len(d.HiddenFP))
	for _, f := range d.OnlyCur {
		fmt.Printf("  NEW  %s:%d %s %s (%s)\n", f.File, f.Line, f.Severity, f.RuleID, f.GOSTType)
	}
	for _, f := range d.OnlyPrev {
		fmt.Printf("  GONE %s:%d %s %s\n", f.File, f.Line, f.Severity, f.RuleID)
	}
	return 0, nil
}

// previousRun возвращает предпоследний запуск относительно cur.
func previousRun(runsDir, cur string) (string, error) {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return "", fmt.Errorf("укажите -prev: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	name := filepath.Base(cur)
	for i, id := range ids {
		if id == name && i > 0 {
			return filepath.Join(runsDir, ids[i-1]), nil
		}
	}
	return "", fmt.Errorf("предыдущий запуск не найден рядом с %s", cur)
}

func cmdQuality(args []string) (int, error) {
	fs := flag.NewFlagSet("quality", flag.ContinueOnError)
	runDir := fs.String("run", "", "каталог запуска по квалификационному набору")
	manifest := fs.String("manifest", "", "описание набора (manifest.json)")
	format := fs.String("format", "text", "text | json | markdown")
	out := fs.String("out", "", "файл отчёта (по умолчанию stdout)")
	maxFP := fs.Float64("max-fp", 50, "порог доли ложноположительных, % (8.4)")
	maxFN := fs.Float64("max-fn", 50, "порог доли пропусков, % (8.4)")
	title := fs.String("title", "Оценка качества статического анализа", "заголовок отчёта")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *runDir == "" || *manifest == "" {
		return 2, fmt.Errorf("нужны -run и -manifest")
	}
	m, err := quality.LoadManifest(*manifest)
	if err != nil {
		return 2, err
	}
	r, err := runs.Load(*runDir)
	if err != nil {
		return 2, err
	}
	store, err := marking.Load(".sgate/markings.json")
	if err != nil {
		return 2, err
	}
	store.Apply(r.Findings)
	res := quality.Measure(m, r.Findings)
	res.Passed = res.FPRate <= *maxFP && res.FNRate <= *maxFN

	var text string
	switch *format {
	case "json":
		raw, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return 2, err
		}
		text = string(raw) + "\n"
	case "markdown":
		text = res.Markdown(*title)
	default:
		text = fmt.Sprintf("набор: ошибок %d, найдено %d, пропущено %d, предупреждений %d, ложных %d\n"+
			"доля ложноположительных (10.4): %.1f %% (порог %.0f)\n"+
			"доля пропусков (10.5): %.1f %% (порог %.0f)\n",
			res.TB, res.TP, res.FN, res.TW, res.FP, res.FPRate, *maxFP, res.FNRate, *maxFN)
		for _, d := range res.Missed {
			text += fmt.Sprintf("  MISS %s:%d %s %s\n", d.File, d.Line, d.Type, d.Note)
		}
		for _, f := range res.FalsePos {
			text += fmt.Sprintf("  FP   %s:%d %s %s (%s)\n", f.File, f.Line, f.Analyzer, f.RuleID, f.GOSTType)
		}
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(text), 0o644); err != nil {
			return 2, err
		}
		fmt.Fprintf(os.Stderr, "отчёт: %s\n", *out)
	} else {
		fmt.Print(text)
	}
	if !res.Passed {
		return 1, nil
	}
	return 0, nil
}

func cmdCatalog(args []string) (int, error) {
	fs := flag.NewFlagSet("catalog", flag.ContinueOnError)
	out := fs.String("out", "", "файл (по умолчанию stdout)")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	doc := gost.CatalogMarkdown()
	if *out != "" {
		if err := os.WriteFile(*out, []byte(doc), 0o644); err != nil {
			return 2, err
		}
		fmt.Fprintf(os.Stderr, "каталог: %s\n", *out)
		return 0, nil
	}
	fmt.Print(doc)
	return 0, nil
}

func cmdRuns(args []string) (int, error) {
	fs := flag.NewFlagSet("runs", flag.ContinueOnError)
	dir := fs.String("dir", ".sgate/runs", "хранилище запусков")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return 2, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta, err := os.ReadFile(*dir + "/" + e.Name() + "/meta.json")
		if err != nil {
			continue
		}
		var m runs.Meta
		if json.Unmarshal(meta, &m) != nil {
			continue
		}
		fmt.Printf("%s  находок %-5d анализаторов %-2d %d мс  %s\n",
			m.ID, m.Total, len(m.Analyzers), m.DurationMS, strings.Join(m.Analyzers, ","))
	}
	return 0, nil
}
