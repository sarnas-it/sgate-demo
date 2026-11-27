// Command corpusgen собирает квалификационный корпус ГОСТ Р 71207-2024
// (10.2 в): программы с заранее известными ошибками на 100 тыс.+ строк.
//
// Корпус генерируется детерминированно и не хранится в git: 10 млн строк в
// репозитории бессмысленны. Каждый пакет — отдельный каталог, чтобы имена
// функций и констант не конфликтовали внутри одной программы.
//
// Манифест совпадает по формату с core/testdata/gost-corpus/manifest.json,
// поэтому sgate quality считает FP/FN тем же кодом.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type defect struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Type string `json:"type"`
	CWE  string `json:"cwe"`
	Note string `json:"note"`
}

type manifest struct {
	Version   int      `json:"version"`
	Tolerance int      `json:"tolerance"`
	Clean     []string `json:"clean"`
	Defects   []defect `json:"defects"`
}

func main() {
	out := flag.String("out", "testdata/corpus-generated", "каталог корпуса")
	defectFiles := flag.Int("defect-files", 160, "файлов с ошибками")
	cleanFiles := flag.Int("clean-files", 40, "чистых файлов")
	fileLines := flag.Int("file-lines", 500, "строк в файле")
	flag.Parse()

	if *fileLines < 60 {
		fmt.Fprintln(os.Stderr, "file-lines должен быть не меньше 60")
		os.Exit(2)
	}
	if err := os.RemoveAll(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if err := os.WriteFile(filepath.Join(*out, "go.mod"),
		[]byte("module corpus\n\ngo 1.26.0\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	m := manifest{Version: 1, Tolerance: 2, Clean: []string{}}

	for i := 0; i < *defectFiles; i++ {
		pkg := fmt.Sprintf("d%04d", i)
		rel := filepath.ToSlash(filepath.Join("defects", pkg, "main.go"))
		content, defects := defectFile(pkg, *fileLines)
		if err := write(*out, rel, content); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		m.Defects = append(m.Defects, defects...)
	}

	for i := 0; i < *cleanFiles; i++ {
		pkg := fmt.Sprintf("c%04d", i)
		rel := filepath.ToSlash(filepath.Join("clean", pkg, "main.go"))
		if err := write(*out, rel, cleanFile(pkg, *fileLines)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		m.Clean = append(m.Clean, rel)
	}

	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.WriteFile(filepath.Join(*out, "manifest.json"), append(raw, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	total := (*defectFiles + *cleanFiles) * *fileLines
	fmt.Printf("корпус: %d файлов, ~%d строк, дефектов %d, чистых файлов %d\n",
		*defectFiles+*cleanFiles, total, len(m.Defects), len(m.Clean))
}

func write(root, rel, content string) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// defectFile собирает пакет с восемью известными ошибками (по одной на тип
// 6.3) и добивает файл безопасным кодом до нужной длины.
func defectFile(pkg string, wantLines int) (string, []defect) {
	var b strings.Builder
	var defects []defect
	line := func(s string) { b.WriteString(s + "\n") }
	mark := func(typ, cwe, note string) {
		defects = append(defects, defect{
			File: filepath.ToSlash(filepath.Join("defects", pkg, "main.go")),
			Line: strings.Count(b.String(), "\n") + 1,
			Type: typ, CWE: cwe, Note: note,
		})
	}

	line("package " + pkg)
	line("")
	line("import (")
	for _, imp := range []string{
		`"crypto/md5"`, `"database/sql"`, `"fmt"`, `"math/rand"`,
		`"net/http"`, `"os"`, `"os/exec"`, `"strconv"`,
	} {
		line("\t" + imp)
	}
	line(")")
	line("")
	line(`const password = "Sup3rS3cretValue"`)
	mark("6.3г", "CWE-798", "секрет в коде")
	line("")
	line("var db *sql.DB")
	line("")

	line("func randToken() int {")
	line("\treturn rand.Int()")
	mark("6.3г", "CWE-338", "math/rand для токена")
	line("}")
	line("")

	line("func hashPass(p string) [16]byte {")
	line("\treturn md5.Sum([]byte(p))")
	mark("6.3г", "CWE-327", "md5")
	line("}")
	line("")

	line("func runCmd(name string) error {")
	line(`	return exec.Command("sh", "-c", name).Run()`)
	mark("6.3а", "CWE-78", "команда из переменной")
	line("}")
	line("")

	line("func readFile(path string) ([]byte, error) {")
	line("\treturn os.ReadFile(path)")
	mark("6.3а", "CWE-22", "путь из переменной")
	line("}")
	line("")

	line("func findUser(r *http.Request) error {")
	line("\tq := r.URL.Query().Get(\"q\")")
	line("\t_, err := db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", q))")
	mark("6.3а", "CWE-89", "SQL через форматную строку")
	line("\treturn err")
	line("}")
	line("")

	line("func pick(r *http.Request, items []string) string {")
	line("\ti, _ := strconv.Atoi(r.URL.Query().Get(\"i\"))")
	line("\treturn items[i]")
	mark("6.3в", "CWE-125", "индекс из запроса")
	line("}")
	line("")

	line("func narrow(n uint64) int32 {")
	line("\treturn int32(n)")
	mark("6.3б", "CWE-190", "сужение разрядности")
	line("}")
	line("")

	for i := 0; strings.Count(b.String(), "\n") < wantLines; i++ {
		line(fmt.Sprintf("func helper%s%d(v int) int {", pkg, i))
		line("\tif v < 0 {")
		line("\t\treturn 0")
		line("\t}")
		line("\treturn v * 2")
		line("}")
		line("")
	}
	return b.String(), defects
}

// cleanFile — безопасный код без классифицируемых находок (10.2 б).
func cleanFile(pkg string, wantLines int) string {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	line("package " + pkg)
	line("")
	for i := 0; strings.Count(b.String(), "\n") < wantLines; i++ {
		line(fmt.Sprintf("func add%s%d(a, b int) int {", pkg, i))
		line("\tif a < 0 || b < 0 {")
		line("\t\treturn 0")
		line("\t}")
		line("\treturn a + b")
		line("}")
		line("")
	}
	return b.String()
}
