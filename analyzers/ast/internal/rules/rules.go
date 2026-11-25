// Package rules — AST-правила, которые не выражаются регулярками semgrep:
// они требуют связей внутри функции (декодирование сообщения → использование
// поля) и понимания структуры узлов.
//
// Пакет не знает про SGATE: на вход каталог, на выход находки. Контракт
// (SGATE_REPO/SGATE_OUT → SARIF) реализован в cmd/ast, поэтому анализатор
// подключается как модуль и может быть заменён на другой язык с тем же
// контрактом.
package rules

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Finding — находка правила.
type Finding struct {
	Rule     string
	Severity string // HIGH | MEDIUM | LOW
	Message  string
	File     string
	Line     int
	Column   int
}

// Rule — описание правила для SARIF.
type Rule struct {
	ID       string
	Severity string
	CWE      string
	Message  string
}

// Catalog — все правила модуля. Порядок стабилен: SARIF не должен меняться
// от запуска к запуску (сравнение прогонов).
func Catalog() []Rule {
	return []Rule{
		{
			ID:       "sgate-ast-broker-entity-subject",
			Severity: "MEDIUM",
			CWE:      "CWE-290",
			Message:  "Entity берётся из payload без сверки с subject: сообщение можно опубликовать в чужой субъект.",
		},
		{
			ID:       "sgate-ast-identity-param",
			Severity: "MEDIUM",
			CWE:      "CWE-639",
			Message:  "Identity-параметр (subject_org/snapshot_id): значение должно приходить из доверенного контекста, а не из пользовательских params.",
		},
	}
}

// Analyze обходит Go-файлы репозитория и возвращает находки и список
// просканированных файлов (для coverage guard SGATE).
func Analyze(root string) ([]Finding, []string, error) {
	var findings []Finding
	var scanned []string
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // недоступный файл не должен валить весь прогон
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" ||
				name == "node_modules" || name == "testdata") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			// Синтаксически битый файл пропускаем: его разберёт компилятор,
			// а анализатор не должен превращать это в ложный ноль.
			fmt.Fprintf(os.Stderr, "ast-skip: %s: %v\n", path, err)
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		scanned = append(scanned, rel)
		findings = append(findings, analyzeFile(fset, rel, file)...)
		return nil
	})
	if err != nil {
		return nil, scanned, err
	}
	return findings, scanned, nil
}

func analyzeFile(fset *token.FileSet, rel string, file *ast.File) []Finding {
	var out []Finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		out = append(out, checkBrokerEntity(fset, rel, fn)...)
	}
	out = append(out, checkIdentityParams(fset, rel, file)...)
	return out
}

// checkBrokerEntity ищет функцию-обработчик, которая декодировала сообщение
// брокера и использует Entity из payload, ни разу не обратившись к Subject.
//
// Это ровно тот случай, который semgrep не выражает: методы с receiver не
// матчатся шаблоном функции, а связь «Unmarshal → поле» требует AST.
func checkBrokerEntity(fset *token.FileSet, rel string, fn *ast.FuncDecl) []Finding {
	msgParams := map[string]bool{}
	for _, p := range fn.Type.Params.List {
		if !isMessageType(p.Type) {
			continue
		}
		for _, n := range p.Names {
			msgParams[n.Name] = true
		}
	}
	if len(msgParams) == 0 {
		return nil
	}

	decoded := map[string]bool{}
	subjectUsed := false
	// Первый проход: что декодировано из Payload параметра и трогали ли Subject.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && msgParams[id.Name] && x.Sel.Name == "Subject" {
				subjectUsed = true
			}
		case *ast.CallExpr:
			fnSel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || fnSel.Sel.Name != "Unmarshal" || len(x.Args) < 2 {
				return true
			}
			if !payloadOfMessage(x.Args[0], msgParams) {
				return true
			}
			if unary, ok := x.Args[1].(*ast.UnaryExpr); ok {
				if id, ok := unary.X.(*ast.Ident); ok {
					decoded[id.Name] = true
				}
			}
		}
		return true
	})
	if subjectUsed || len(decoded) == 0 {
		return nil
	}

	var out []Finding
	seen := map[int]bool{}
	// Второй проход: где используется Entity декодированной структуры.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || !decoded[id.Name] || sel.Sel.Name != "Entity" {
			return true
		}
		pos := fset.Position(sel.Pos())
		if seen[pos.Line] {
			return true
		}
		seen[pos.Line] = true
		out = append(out, Finding{
			Rule:     "sgate-ast-broker-entity-subject",
			Severity: "MEDIUM",
			Message:  fmt.Sprintf("Entity из payload (%s.Entity) используется без сверки с subject сообщения", id.Name),
			File:     rel,
			Line:     pos.Line,
			Column:   pos.Column,
		})
		return true
	})
	return out
}

func isMessageType(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Message"
}

func payloadOfMessage(arg ast.Expr, msgParams map[string]bool) bool {
	sel, ok := arg.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && msgParams[id.Name] && sel.Sel.Name == "Payload"
}

// checkIdentityParams ищет identity-параметры, которые код берёт из
// пользовательского словаря: params["subject_org"], params["snapshot_id"]
// и ключи таких словарей. Это точка, где арендатор выбирается вызывающим.
func checkIdentityParams(fset *token.FileSet, rel string, file *ast.File) []Finding {
	keys := map[string]bool{"subject_org": true, "snapshot_id": true}
	var out []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		var lit *ast.BasicLit
		switch x := n.(type) {
		case *ast.IndexExpr:
			lit, _ = x.Index.(*ast.BasicLit)
		case *ast.KeyValueExpr:
			lit, _ = x.Key.(*ast.BasicLit)
		default:
			return true
		}
		if lit == nil || lit.Kind != token.STRING {
			return true
		}
		key := strings.Trim(lit.Value, `"`)
		if !keys[key] {
			return true
		}
		pos := fset.Position(lit.Pos())
		out = append(out, Finding{
			Rule:     "sgate-ast-identity-param",
			Severity: "MEDIUM",
			Message:  fmt.Sprintf("identity-параметр %q берётся из словаря: проверьте, что значение доверенное, а не из тела запроса", key),
			File:     rel,
			Line:     pos.Line,
			Column:   pos.Column,
		})
		return true
	})
	return out
}
