package taint

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func rulesOf(fs []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Rule]++
	}
	return out
}

const goMod = "module example.com/app\n\ngo 1.26\n"

// Цепочка из трёх пакетов: источник в api, сток в repo.
func TestCrossPackageSQL(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": goMod,
		"internal/api/handler.go": `package api

import (
	"net/http"

	"example.com/app/internal/service"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	_ = service.Search(r.Context(), q)
}
`,
		"internal/service/service.go": `package service

import (
	"context"

	"example.com/app/internal/repo"
)

func Search(ctx context.Context, q string) error {
	return repo.Find(ctx, q)
}
`,
		"internal/repo/repo.go": `package repo

import (
	"context"
	"database/sql"
)

var db *sql.DB

func Find(ctx context.Context, q string) error {
	_, err := db.QueryContext(ctx, "SELECT * FROM t WHERE name = '"+q+"'")
	return err
}
`,
	})

	findings, scanned, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 3 {
		t.Fatalf("scanned = %v", scanned)
	}
	if got := rulesOf(findings)["sgate-taint-sql"]; got != 1 {
		t.Fatalf("ожидалась 1 находка SQL через три пакета, получено %d: %+v", got, findings)
	}
	if findings[0].File != "internal/repo/repo.go" {
		t.Fatalf("находка не в стоке: %+v", findings[0])
	}
}

// Параметризованный запрос безопасен: taint в аргументе, не в тексте.
func TestParameterizedQueryNotFlagged(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": goMod,
		"internal/api/handler.go": `package api

import (
	"net/http"

	"example.com/app/internal/repo"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	_ = repo.Find(r.Context(), q)
}
`,
		"internal/repo/repo.go": `package repo

import (
	"context"
	"database/sql"
)

var db *sql.DB

func Find(ctx context.Context, q string) error {
	_, err := db.QueryContext(ctx, "SELECT * FROM t WHERE name = $1", q)
	return err
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := rulesOf(findings)["sgate-taint-sql"]; n != 0 {
		t.Fatalf("параметризованный запрос не должен флагиться: %+v", findings)
	}
}

// Санитайзер (Atoi) снимает taint.
func TestSanitizerStopsTaint(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": goMod,
		"internal/api/handler.go": `package api

import (
	"net/http"
	"strconv"

	"example.com/app/internal/repo"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("id")
	n, _ := strconv.Atoi(raw)
	_ = repo.Find(r.Context(), strconv.Itoa(n))
}
`,
		"internal/repo/repo.go": `package repo

import (
	"context"
	"database/sql"
)

var db *sql.DB

func Find(ctx context.Context, q string) error {
	_, err := db.QueryContext(ctx, "SELECT * FROM t WHERE name = '"+q+"'")
	return err
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := rulesOf(findings)["sgate-taint-sql"]; n != 0 {
		t.Fatalf("после Atoi taint должен сниматься: %+v", findings)
	}
}

// Второй сток: exec.Command через пакет.
func TestCrossPackageCommand(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": goMod,
		"internal/api/handler.go": `package api

import (
	"net/http"

	"example.com/app/internal/runner"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	arg := r.FormValue("host")
	_ = runner.Ping(arg)
}
`,
		"internal/runner/run.go": `package runner

import "os/exec"

func Ping(host string) error {
	return exec.Command("ping", "-c", "1", host).Run()
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := rulesOf(findings)["sgate-taint-command"]; n != 1 {
		t.Fatalf("ожидалась находка command-injection: %+v", findings)
	}
}

// Нет источника — нет находки.
func TestNoSourceNoFinding(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": goMod,
		"internal/repo/repo.go": `package repo

import (
	"context"
	"database/sql"
)

var db *sql.DB

func Find(ctx context.Context) error {
	_, err := db.QueryContext(ctx, "SELECT * FROM t WHERE name = 'static'")
	return err
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("без источника находок быть не должно: %+v", findings)
	}
}

// taint через возвращаемое значение: helper возвращает ввод, сток в другом пакете.
func TestReturnTaint(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": goMod,
		"internal/api/handler.go": `package api

import (
	"net/http"

	"example.com/app/internal/repo"
	"example.com/app/internal/input"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	q := input.Query(r)
	_ = repo.Find(r.Context(), q)
}
`,
		"internal/input/input.go": `package input

import "net/http"

func Query(r *http.Request) string {
	return r.URL.Query().Get("q")
}
`,
		"internal/repo/repo.go": `package repo

import (
	"context"
	"database/sql"
)

var db *sql.DB

func Find(ctx context.Context, q string) error {
	_, err := db.QueryContext(ctx, "SELECT * FROM t WHERE name = '"+q+"'")
	return err
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := rulesOf(findings)["sgate-taint-sql"]; n != 1 {
		t.Fatalf("taint через возврат функции не отслежен: %+v", findings)
	}
}
