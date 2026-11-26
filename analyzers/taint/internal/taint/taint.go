// Package taint — межпакетный анализ помеченных данных по AST.
//
// Semgrep OSS работает внутри функции, gosec — в пределах пакета. Этот
// проход строит индекс функций по всему репозиторию и переносит taint через
// аргументы и возвращаемые значения, поэтому ловит цепочку
// «HTTP-хендлер → сервис → репозиторий → SQL/exec».
//
// Пакет не знает про SGATE: на вход каталог, на выход находки.
package taint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Finding — находка.
type Finding struct {
	Rule     string
	Severity string
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

// Catalog — стабильный список правил.
func Catalog() []Rule {
	return []Rule{
		{ID: "sgate-taint-sql", Severity: "HIGH", CWE: "CWE-89",
			Message: "Данные запроса доходят до SQL-запроса через несколько пакетов без параметризации."},
		{ID: "sgate-taint-command", Severity: "HIGH", CWE: "CWE-78",
			Message: "Данные запроса доходят до запуска процесса через несколько пакетов."},
		{ID: "sgate-taint-file", Severity: "MEDIUM", CWE: "CWE-22",
			Message: "Данные запроса доходят до пути файла через несколько пакетов."},
		{ID: "sgate-taint-ssrf", Severity: "MEDIUM", CWE: "CWE-918",
			Message: "Данные запроса доходят до исходящего HTTP-запроса через несколько пакетов."},
	}
}

// maxRounds — предохранитель fixpoint: цепочки глубже не анализируются.
const maxRounds = 8

type pkg struct {
	name    string
	dir     string
	imports map[string]string // alias -> import path
	funcs   []*fn
}

type fn struct {
	key      string
	pkg      *pkg
	name     string
	decl     *ast.FuncDecl
	file     string
	params   []string
	tainted  map[string]bool // имена локальных переменных
	paramsT  map[int]bool    // tainted-параметры по индексу
	retTaint bool
}

type program struct {
	root       string
	modulePath string
	fset       *token.FileSet
	pkgs       map[string]*pkg // dir -> pkg
	funcs      []*fn
	byName     map[string][]*fn
	findings   []Finding
	seen       map[string]bool
	changed    bool
}

// Analyze обходит репозиторий и возвращает находки и список файлов.
func Analyze(root string) ([]Finding, []string, error) {
	modulePath := readModulePath(root)
	p := &program{
		root:       root,
		modulePath: modulePath,
		fset:       token.NewFileSet(),
		pkgs:       map[string]*pkg{},
		byName:     map[string][]*fn{},
		seen:       map[string]bool{},
	}

	var scanned []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && path != root {
				switch d.Name() {
				case "vendor", "testdata", "node_modules":
					return fs.SkipDir
				}
				if strings.HasPrefix(d.Name(), ".") {
					return fs.SkipDir
				}
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
		file, err := parser.ParseFile(p.fset, path, src, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "taint-skip: %s: %v\n", path, err)
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		dir := filepath.Dir(rel)
		pk := p.pkgs[dir]
		if pk == nil {
			pk = &pkg{name: file.Name.Name, dir: dir, imports: map[string]string{}}
			p.pkgs[dir] = pk
		}
		for _, imp := range file.Imports {
			ipath := strings.Trim(imp.Path.Value, `"`)
			alias := ""
			if imp.Name != nil {
				alias = imp.Name.Name
			} else {
				alias = ipath[strings.LastIndex(ipath, "/")+1:]
			}
			pk.imports[alias] = ipath
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			f := &fn{
				key:     dir + "#" + funcName(fd),
				pkg:     pk,
				name:    funcName(fd),
				decl:    fd,
				file:    rel,
				tainted: map[string]bool{},
				paramsT: map[int]bool{},
			}
			for _, param := range fd.Type.Params.List {
				for _, n := range param.Names {
					f.params = append(f.params, n.Name)
				}
			}
			p.funcs = append(p.funcs, f)
			p.byName[f.name] = append(p.byName[f.name], f)
			pk.funcs = append(pk.funcs, f)
		}
		scanned = append(scanned, rel)
		return nil
	})
	if err != nil {
		return nil, scanned, err
	}

	for round := 0; round < maxRounds; round++ {
		p.changed = false
		for _, f := range p.funcs {
			p.analyzeFunc(f)
		}
		if !p.changed {
			break
		}
	}
	return p.findings, scanned, nil
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		recv := exprName(fd.Recv.List[0].Type)
		return recv + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func exprName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return exprName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return exprName(x.X)
	case *ast.IndexListExpr:
		return exprName(x.X)
	default:
		return ""
	}
}

func readModulePath(root string) string {
	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func (p *program) analyzeFunc(f *fn) {
	local := map[string]bool{}
	for k := range f.tainted {
		local[k] = true
	}
	for i := range f.params {
		if f.paramsT[i] {
			local[f.params[i]] = true
		}
	}
	p.walkStmts(f, f.decl.Body.List, local)
}

func (p *program) walkStmts(f *fn, stmts []ast.Stmt, local map[string]bool) {
	for _, stmt := range stmts {
		p.walkStmt(f, stmt, local)
	}
}

func (p *program) walkStmt(f *fn, stmt ast.Stmt, local map[string]bool) {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		p.handleCalls(f, s.Rhs, local)
		tainted := false
		for _, rhs := range s.Rhs {
			if p.exprTainted(rhs, local) {
				tainted = true
				break
			}
		}
		if !tainted {
			for _, rhs := range s.Rhs {
				if call, ok := rhs.(*ast.CallExpr); ok && p.calleeReturnsTaintedFn(call, f) {
					tainted = true
					break
				}
			}
		}
		if tainted {
			for _, lhs := range s.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					if !local[id.Name] {
						local[id.Name] = true
						p.changed = true
					}
				}
			}
		}
	case *ast.DeclStmt:
		// var x = ... — эквивалент присваивания.
		if gd, ok := s.Decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for i, name := range vs.Names {
						if i < len(vs.Values) && p.exprTainted(vs.Values[i], local) {
							local[name.Name] = true
						}
					}
				}
			}
		}
	case *ast.ExprStmt:
		p.handleCalls(f, []ast.Expr{s.X}, local)
	case *ast.ReturnStmt:
		p.handleCalls(f, s.Results, local)
		for _, res := range s.Results {
			if p.exprTainted(res, local) && !f.retTaint {
				f.retTaint = true
				p.changed = true
			}
		}
	case *ast.IfStmt:
		p.handleCalls(f, []ast.Expr{s.Cond}, local)
		p.walkStmts(f, s.Body.List, local)
		if s.Else != nil {
			p.walkStmt(f, s.Else, local)
		}
	case *ast.ForStmt:
		p.handleCalls(f, []ast.Expr{s.Cond}, local)
		p.walkStmts(f, s.Body.List, local)
	case *ast.RangeStmt:
		p.handleCalls(f, []ast.Expr{s.X}, local)
		p.walkStmts(f, s.Body.List, local)
	case *ast.BlockStmt:
		p.walkStmts(f, s.List, local)
	case *ast.SwitchStmt:
		p.handleCalls(f, []ast.Expr{s.Tag}, local)
		p.walkStmts(f, s.Body.List, local)
	case *ast.TypeSwitchStmt:
		p.walkStmts(f, s.Body.List, local)
	case *ast.SelectStmt:
		p.walkStmts(f, s.Body.List, local)
	case *ast.LabeledStmt:
		p.walkStmt(f, s.Stmt, local)
	case *ast.DeferStmt:
		p.handleCalls(f, []ast.Expr{s.Call}, local)
	case *ast.GoStmt:
		p.handleCalls(f, []ast.Expr{s.Call}, local)
	case *ast.CaseClause:
		p.walkStmts(f, s.Body, local)
	case *ast.CommClause:
		p.walkStmts(f, s.Body, local)
	}
}

func (p *program) handleCalls(f *fn, exprs []ast.Expr, local map[string]bool) {
	for _, e := range exprs {
		if e == nil {
			continue // for {} / switch без тега: выражения нет
		}
		ast.Inspect(e, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sink := sinkRule(call); sink != "" {
				if sink == "sgate-taint-sql" {
					// Параметризованный запрос безопасен: taint должен быть
					// в самом тексте запроса, а не в отдельном аргументе.
					if p.sqlQueryTainted(call, local) {
						p.report(sink, f, call)
					}
				} else if p.callTainted(call, local) {
					p.report(sink, f, call)
				}
			}
			if isDecodeIntoRequest(call) && len(call.Args) > 0 {
				if unary, ok := call.Args[len(call.Args)-1].(*ast.UnaryExpr); ok {
					if id, ok := unary.X.(*ast.Ident); ok && !local[id.Name] {
						local[id.Name] = true
						p.changed = true
					}
				}
			}
			if callee := p.resolveCall(f, call); callee != nil {
				for i, arg := range call.Args {
					if p.exprTainted(arg, local) && !callee.paramsT[i] {
						callee.paramsT[i] = true
						p.changed = true
					}
				}
			}
			return true
		})
	}
}

// sqlQueryTainted — taint в аргументе-запросе (а не в списке параметров).
func (p *program) sqlQueryTainted(call *ast.CallExpr, local map[string]bool) bool {
	if len(call.Args) == 0 {
		return false
	}
	idx := 0
	if len(call.Args) > 1 && looksLikeContext(call.Args[0]) {
		idx = 1
	}
	if idx >= len(call.Args) {
		return false
	}
	return p.exprTainted(call.Args[idx], local)
}

func looksLikeContext(e ast.Expr) bool {
	name := ""
	switch x := e.(type) {
	case *ast.Ident:
		name = x.Name
	case *ast.SelectorExpr:
		name = x.Sel.Name
	case *ast.CallExpr:
		name = receiverChainName(x.Fun)
	}
	name = strings.ToLower(name)
	return strings.Contains(name, "ctx") || strings.Contains(name, "context")
}

func (p *program) callTainted(call *ast.CallExpr, local map[string]bool) bool {
	for _, arg := range call.Args {
		if p.exprTainted(arg, local) {
			return true
		}
	}
	return false
}

func (p *program) calleeReturnsTaintedFn(call *ast.CallExpr, f *fn) bool {
	if f == nil {
		return false
	}
	callee := p.resolveCall(f, call)
	return callee != nil && callee.retTaint
}

func (p *program) resolveCall(caller *fn, call *ast.CallExpr) *fn {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return p.resolveInPkg(caller.pkg, fun.Name)
	case *ast.SelectorExpr:
		if id, ok := fun.X.(*ast.Ident); ok {
			if ipath, ok := caller.pkg.imports[id.Name]; ok {
				if dir := p.dirForImport(ipath); dir != "" {
					if pk := p.pkgs[dir]; pk != nil {
						return p.resolveInPkg(pk, fun.Sel.Name)
					}
				}
			}
		}
		// Метод или функция другого пакета: ищем по имени, если однозначно.
		return p.resolveUnique(fun.Sel.Name)
	case *ast.IndexExpr:
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			return p.resolveUnique(sel.Sel.Name)
		}
	}
	return nil
}

func (p *program) resolveInPkg(pk *pkg, name string) *fn {
	for _, f := range pk.funcs {
		if f.name == name || strings.HasSuffix(f.name, "."+name) {
			return f
		}
	}
	return nil
}

func (p *program) resolveUnique(name string) *fn {
	cands := p.byName[name]
	if len(cands) == 1 {
		return cands[0]
	}
	return nil
}

func (p *program) dirForImport(ipath string) string {
	if p.modulePath == "" {
		return ""
	}
	if ipath == p.modulePath {
		return "."
	}
	if strings.HasPrefix(ipath, p.modulePath+"/") {
		return strings.TrimPrefix(ipath, p.modulePath+"/")
	}
	return ""
}

func (p *program) report(rule string, f *fn, call *ast.CallExpr) {
	pos := p.fset.Position(call.Pos())
	key := rule + "|" + f.file + "|" + strconv.Itoa(pos.Line)
	if p.seen[key] {
		return
	}
	p.seen[key] = true
	p.findings = append(p.findings, Finding{
		Rule:     rule,
		Severity: severityOf(rule),
		Message:  messageOf(rule) + " (" + f.decl.Name.Name + ")",
		File:     f.file,
		Line:     pos.Line,
		Column:   pos.Column,
	})
}

func severityOf(rule string) string {
	for _, r := range Catalog() {
		if r.ID == rule {
			return r.Severity
		}
	}
	return "MEDIUM"
}

func messageOf(rule string) string {
	for _, r := range Catalog() {
		if r.ID == rule {
			return r.Message
		}
	}
	return rule
}

// exprTainted — помечено ли выражение. Санитайзеры снимают taint.
func (p *program) exprTainted(e ast.Expr, local map[string]bool) bool {
	switch x := e.(type) {
	case nil:
		return false
	case *ast.Ident:
		return local[x.Name]
	case *ast.ParenExpr:
		return p.exprTainted(x.X, local)
	case *ast.SelectorExpr:
		return p.exprTainted(x.X, local)
	case *ast.IndexExpr:
		return p.exprTainted(x.X, local) || p.exprTainted(x.Index, local)
	case *ast.StarExpr:
		return p.exprTainted(x.X, local)
	case *ast.UnaryExpr:
		return p.exprTainted(x.X, local)
	case *ast.BinaryExpr:
		return p.exprTainted(x.X, local) || p.exprTainted(x.Y, local)
	case *ast.CompositeLit:
		for _, el := range x.Elts {
			if p.exprTainted(el, local) {
				return true
			}
		}
		return false
	case *ast.TypeAssertExpr:
		return p.exprTainted(x.X, local)
	case *ast.CallExpr:
		if isSanitizer(x) {
			return false
		}
		if isSource(x) {
			return true
		}
		for _, arg := range x.Args {
			if p.exprTainted(arg, local) {
				return true
			}
		}
		return false
	case *ast.FuncLit:
		return false
	}
	return false
}

func selectorName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

func receiverChainName(e ast.Expr) string {
	var parts []string
	for {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			parts = append(parts, x.Sel.Name)
			e = x.X
		case *ast.CallExpr:
			// r.URL.Query().Get(...) — цепочка через вызов.
			parts = append(parts, receiverChainName(x.Fun))
			return strings.Join(parts, ".")
		case *ast.Ident:
			parts = append(parts, x.Name)
			return strings.Join(parts, ".")
		default:
			return strings.Join(parts, ".")
		}
	}
}

// isSource — чтение пользовательского ввода.
func isSource(call *ast.CallExpr) bool {
	name := selectorName(call.Fun)
	chain := receiverChainName(call.Fun)
	switch name {
	case "FormValue", "PostFormValue", "PathValue":
		return true
	case "Get":
		if strings.Contains(chain, "Query") || strings.Contains(chain, "Header") || strings.Contains(chain, "Form") {
			return true
		}
	}
	if isDecodeIntoRequest(call) {
		return true
	}
	if name == "ReadAll" {
		for _, arg := range call.Args {
			if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "Body" {
				return true
			}
		}
	}
	return false
}

func isDecodeIntoRequest(call *ast.CallExpr) bool {
	if selectorName(call.Fun) != "Decode" || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	inner, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	name := selectorName(inner.Fun)
	return name == "NewDecoder" || name == "NewRequest"
}

// isSanitizer — функции, после которых значение нельзя использовать как
// инъекцию (число, нормализованный путь, экранирование).
func isSanitizer(call *ast.CallExpr) bool {
	name := selectorName(call.Fun)
	if name == "" {
		if id, ok := call.Fun.(*ast.Ident); ok {
			name = id.Name
		}
	}
	switch name {
	case "Atoi", "ParseInt", "ParseUint", "ParseFloat", "ParseBool",
		"Base", "Clean", "QueryEscape", "PathEscape", "EscapeString", "Parse":
		return true
	}
	return false
}

// sinkRule — правило для вызова-стока; пустая строка — не сток.
func sinkRule(call *ast.CallExpr) string {
	chain := receiverChainName(call.Fun)
	name := selectorName(call.Fun)
	if name == "" {
		if id, ok := call.Fun.(*ast.Ident); ok {
			name = id.Name
		}
	}
	switch name {
	case "Query", "QueryContext", "QueryRow", "QueryRowContext", "Exec", "ExecContext":
		return "sgate-taint-sql"
	case "Command", "CommandContext":
		if strings.Contains(chain, "exec") || name == "Command" {
			return "sgate-taint-command"
		}
	case "Open", "OpenFile", "ReadFile", "WriteFile":
		if strings.Contains(chain, "os") || strings.Contains(chain, "ioutil") {
			return "sgate-taint-file"
		}
	case "Get", "Post", "NewRequest", "NewRequestWithContext":
		if strings.Contains(chain, "http") {
			return "sgate-taint-ssrf"
		}
	}
	return ""
}
