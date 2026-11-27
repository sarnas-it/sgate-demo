// Package analysis — SSA-проход SGATE: межпроцедурный taint с косвенными
// вызовами.
//
// AST-модули разрешают вызовы по импортам и уникальным именам, но не видят
// func-значения в структурах (go-test-bench: Sink.Handler = method, вызов
// sink.Handler(...)). SSA + CHA разрешает такие вызовы по типу, поэтому поток
// «ввод → обработчик → SQL» находится и там.
package analysis

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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

// Rule — описание правила.
type Rule struct {
	ID       string
	Severity string
	CWE      string
	Message  string
}

// Catalog — правила модуля.
func Catalog() []Rule {
	return []Rule{
		{ID: "sgate-ssa-taint-sql", Severity: "HIGH", CWE: "CWE-89",
			Message: "Ввод пользователя через цепочку вызовов (включая косвенные) доходит до SQL-запроса."},
		{ID: "sgate-ssa-taint-command", Severity: "HIGH", CWE: "CWE-78",
			Message: "Ввод пользователя через цепочку вызовов доходит до запуска процесса."},
		{ID: "sgate-ssa-taint-file", Severity: "MEDIUM", CWE: "CWE-22",
			Message: "Ввод пользователя через цепочку вызовов доходит до пути файла."},
		{ID: "sgate-ssa-taint-ssrf", Severity: "MEDIUM", CWE: "CWE-918",
			Message: "Ввод пользователя через цепочку вызовов доходит до исходящего HTTP-запроса."},
	}
}

type analyzer struct {
	root     string
	fset     *token.FileSet
	siteCal  map[ssa.CallInstruction][]*ssa.Function
	findings []Finding
	seen     map[string]bool
	// taintedParams — какие параметры функций помечены.
	taintedParams map[*ssa.Function]map[int]bool
	returnTainted map[*ssa.Function]bool
	// reachable — функции, достижимые из HTTP-обработчиков. Сток вне этого
	// множества (CLI, фоновые задачи) не отчёт: ввод там не от запроса, а
	// контекстно-независимый taint иначе даёт ложные срабатывания.
	reachable map[*ssa.Function]bool
	changed   bool
}

// Analyze загружает пакеты, строит SSA и ищет поток «источник → сток».
func Analyze(root string) ([]Finding, []string, error) {
	// Отчёт считает пути относительно корня, поэтому корень должен быть
	// абсолютным: иначе filepath.Rel даёт "../..." и находка отбрасывается.
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedTypesSizes |
			packages.NeedModule,
		Dir:   root,
		Tests: false,
		Env:   append(envWithoutWorkspace(), "GOFLAGS=-mod=mod"),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, nil, fmt.Errorf("load packages: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, nil, nil
	}
	// Ошибки типов не должны валить прогон: часть пакетов может не собираться
	// без зависимостей, но SSA для остальных строится.
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	a := &analyzer{
		root:          root,
		fset:          prog.Fset,
		siteCal:       map[ssa.CallInstruction][]*ssa.Function{},
		seen:          map[string]bool{},
		taintedParams: map[*ssa.Function]map[int]bool{},
		returnTainted: map[*ssa.Function]bool{},
		reachable:     map[*ssa.Function]bool{},
	}

	// RTA точнее CHA: строит рёбра по реально созданным типам, поэтому
	// функции CLI не попадают в граф «по совпадению сигнатуры». Для косвенных
	// вызовов (func-значения, интерфейсы) рёбра тоже есть.
	cg := buildCallGraph(prog, ssaPkgs)
	callgraph.GraphVisitEdges(cg, func(edge *callgraph.Edge) error {
		if edge.Site != nil && edge.Callee != nil && edge.Callee.Func != nil {
			a.siteCal[edge.Site] = append(a.siteCal[edge.Site], edge.Callee.Func)
		}
		return nil
	})

	var scanned []string
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			pos := prog.Fset.Position(f.Pos())
			if pos.Filename == "" {
				continue
			}
			rel, err := filepath.Rel(root, pos.Filename)
			if err != nil {
				rel = pos.Filename
			}
			scanned = append(scanned, rel)
		}
	}
	_ = ssaPkgs

	// Fixpoint по функциям: taint переносится и через параметры, и через
	// возвращаемые значения, поэтому одного прохода недостаточно.
	all := make([]*ssa.Function, 0, 256)
	for f := range ssautil.AllFunctions(prog) {
		if f.Blocks == nil || isWrapper(f) {
			continue
		}
		if !a.inProject(f) {
			continue
		}
		all = append(all, f)
	}

	a.reachable = httpReachable(cg, all)
	for round := 0; round < 10; round++ {
		a.changed = false
		for _, f := range all {
			a.analyze(f)
		}
		if !a.changed {
			break
		}
	}
	return a.findings, scanned, nil
}

func envWithoutWorkspace() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GOWORK=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GOWORK=off")
}

// buildCallGraph — RTA от точек входа; CHA остаётся запасным вариантом,
// когда в наборе нет main-пакетов (библиотека).
func buildCallGraph(prog *ssa.Program, ssaPkgs []*ssa.Package) *callgraph.Graph {
	var roots []*ssa.Function
	for _, mp := range ssautil.MainPackages(ssaPkgs) {
		for _, m := range mp.Members {
			if f, ok := m.(*ssa.Function); ok {
				roots = append(roots, f)
			}
		}
	}
	if len(roots) > 0 {
		if res := rta.Analyze(roots, true); res != nil && res.CallGraph != nil {
			return res.CallGraph
		}
	}
	return cha.CallGraph(prog)
}

// httpReachable — функции, достижимые по графу вызовов (CHA, включая
// косвенные) из HTTP-обработчиков.
func httpReachable(cg *callgraph.Graph, funcs []*ssa.Function) map[*ssa.Function]bool {
	seen := map[*ssa.Function]bool{}
	stack := make([]*ssa.Function, 0, 16)
	for _, f := range funcs {
		if isHTTPHandler(f) {
			seen[f] = true
			stack = append(stack, f)
		}
	}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node := cg.Nodes[f]
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			callee := edge.Callee
			if callee == nil || callee.Func == nil || seen[callee.Func] {
				continue
			}
			seen[callee.Func] = true
			stack = append(stack, callee.Func)
		}
	}
	return seen
}

// isHTTPHandler — сигнатура func(http.ResponseWriter, *http.Request) или
// метод ServeHTTP.
func isHTTPHandler(f *ssa.Function) bool {
	if f == nil {
		return false
	}
	if f.Name() == "ServeHTTP" && f.Signature != nil && f.Signature.Params().Len() == 2 {
		return true
	}
	sig := f.Signature
	if sig == nil || sig.Params().Len() != 2 || sig.Results().Len() != 0 {
		return false
	}
	first := sig.Params().At(0).Type().String()
	second := sig.Params().At(1).Type().String()
	return first == "net/http.ResponseWriter" && second == "*net/http.Request"
}

// inProject — функция объявлена в файлах проекта. Проверка по файлу, а не по
// пакету: у анонимных функций (обработчики http) Pkg равен nil, и фильтр по
// пакету выкидывал всю логику хендлеров.
func (a *analyzer) inProject(f *ssa.Function) bool {
	if f == nil {
		return false
	}
	pos := f.Pos()
	if !pos.IsValid() {
		return false
	}
	rel, err := filepath.Rel(a.root, a.fset.Position(pos).Filename)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

func isWrapper(f *ssa.Function) bool {
	// Синтетические обёртки не несут логики и только шумят в fixpoint.
	return strings.HasPrefix(f.Name(), "bound$") || strings.HasPrefix(f.Name(), "thunk$")
}

// analyze — внутрипроцедурный taint с передачей в вызываемые функции.
func (a *analyzer) analyze(fn *ssa.Function) {
	tainted := map[ssa.Value]bool{}
	for i, p := range fn.Params {
		if a.taintedParams[fn][i] {
			tainted[p] = true
		}
	}

	changed := true
	for changed {
		changed = false
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				if v, ok := instr.(ssa.Value); ok {
					// Источник (ввод запроса) заражает результат вызова.
					if call, ok := instr.(ssa.CallInstruction); ok {
						if isSourceValue(v) && !tainted[v] {
							tainted[v] = true
							changed = true
						}
						if a.callReturnsTainted(call) && !tainted[v] {
							tainted[v] = true
							changed = true
						}
					}
				}
				// Вариадические вызовы, поля структур и замыкания идут через
				// память: fmt.Sprintf("%s", q) кладёт q в массив и передаёт
				// срез. Поэтому заражённое значение заражает свой адрес.
				// Тело HTTP-запроса — источник; ReadAll сам по себе
				// источником не является (читает и файлы, и буферы).
				if fa, ok := instr.(*ssa.FieldAddr); ok && isRequestBody(fa) {
					if !tainted[fa] {
						tainted[fa] = true
						changed = true
					}
				}
				if store, ok := instr.(*ssa.Store); ok && tainted[store.Val] {
					if a.markAddress(store.Addr, tainted) {
						changed = true
					}
				}
				if a.instructionTainted(instr, tainted) {
					if v, ok := instr.(ssa.Value); ok && !tainted[v] {
						tainted[v] = true
						changed = true
					}
					// Данные приходят не только результатом: json.Decode(&body)
					// пишет их в указатель. Заражаем цель, если заражён сам
					// вызов (например, декодер поверх тела запроса).
					if call, ok := instr.(*ssa.Call); ok && tainted[call] {
						if a.markSourceArgs(call.Common(), tainted) {
							changed = true
						}
					}
				}
				a.handleCall(fn, instr, tainted)
			}
		}
	}

	// Возвращаемое значение заражено — передадим это вызывающим на следующем
	// раунде fixpoint.
	for _, block := range fn.Blocks {
		ret, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return)
		if !ok {
			continue
		}
		for _, res := range ret.Results {
			if tainted[res] && !a.returnTainted[fn] {
				a.returnTainted[fn] = true
				a.changed = true
			}
		}
	}
}

func (a *analyzer) callReturnsTainted(call ssa.CallInstruction) bool {
	for _, callee := range a.callees(call) {
		if callee != nil && a.returnTainted[callee] {
			return true
		}
	}
	return false
}

// isRequestBody — обращение к полю Body у *http.Request.
func isRequestBody(fa *ssa.FieldAddr) bool {
	t := fa.X.Type().String()
	return strings.Contains(t, "net/http.Request") && fieldName(fa) == "Body"
}

func fieldName(fa *ssa.FieldAddr) string {
	t := fa.X.Type()
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	structType, ok := t.Underlying().(*types.Struct)
	if !ok || fa.Field >= structType.NumFields() {
		return ""
	}
	return structType.Field(fa.Field).Name()
}

// unwrapInterface снимает обёртки MakeInterface/ChangeInterface/ChangeType.
func unwrapInterface(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		default:
			return v
		}
	}
}

// markSourceArgs заражает указатели, в которые источник пишет данные
// (Decode(&body), Unmarshal(data, &body)).
func (a *analyzer) markSourceArgs(common *ssa.CallCommon, tainted map[ssa.Value]bool) bool {
	name, _, _ := callInfo(common)
	if name != "Decode" && name != "Unmarshal" {
		return false
	}
	changed := false
	for _, arg := range common.Args {
		// Decode принимает any: указатель приходит обёрнутым в MakeInterface.
		target := unwrapInterface(arg)
		if _, ok := target.Type().Underlying().(*types.Pointer); ok {
			if a.markAddress(target, tainted) {
				changed = true
			}
		}
	}
	return changed
}

// markAddress заражает значение-адрес и его базу: IndexAddr/FieldAddr →
// исходный массив или структура, чтобы срез и чтение поля тоже были
// заражены.
func (a *analyzer) markAddress(addr ssa.Value, tainted map[ssa.Value]bool) bool {
	changed := false
	for addr != nil {
		if !tainted[addr] {
			tainted[addr] = true
			changed = true
		}
		switch v := addr.(type) {
		case *ssa.IndexAddr:
			addr = v.X
		case *ssa.FieldAddr:
			addr = v.X
		case *ssa.Slice:
			addr = v.X
		default:
			return changed
		}
	}
	return changed
}

func (a *analyzer) instructionTainted(instr ssa.Instruction, tainted map[ssa.Value]bool) bool {
	// Значение инструкции заражено, если заражён любой операнд. Для Phi это
	// даёт корректный fixpoint, для остальных — консервативно.
	operands := instr.Operands(nil)
	for _, op := range operands {
		if op != nil && tainted[*op] {
			return true
		}
	}
	return false
}

func (a *analyzer) handleCall(fn *ssa.Function, instr ssa.Instruction, tainted map[ssa.Value]bool) {
	call, ok := instr.(ssa.CallInstruction)
	if !ok {
		return
	}
	common := call.Common()
	if rule := a.sinkRule(common, tainted); rule != "" {
		a.report(rule, call, fn)
	}

	callees := a.callees(call)
	if len(callees) == 0 {
		return
	}
	for _, callee := range callees {
		if callee == nil || callee.Blocks == nil {
			continue
		}
		for i, arg := range common.Args {
			if !tainted[arg] {
				continue
			}
			if a.taintedParams[callee] == nil {
				a.taintedParams[callee] = map[int]bool{}
			}
			// Статический вызов метода: получатель входит в Args, индексы
			// совпадают с Params. Косвенный вызов (func-значение) и invoke:
			// получателя в Args нет, параметры callee сдвинуты на один.
			shift := 0
			if callee.Signature != nil && callee.Signature.Recv() != nil && common.StaticCallee() != callee {
				shift = 1
			}
			idx := i + shift
			if idx >= len(callee.Params) {
				continue
			}
			if !a.taintedParams[callee][idx] {
				a.taintedParams[callee][idx] = true
				a.changed = true
			}
		}
	}
}

func (a *analyzer) callees(call ssa.CallInstruction) []*ssa.Function {
	if static := call.Common().StaticCallee(); static != nil {
		return []*ssa.Function{static}
	}
	return a.siteCal[call]
}

// sinkRule проверяет, является ли вызов стоком с заражённым аргументом.
func (a *analyzer) sinkRule(common *ssa.CallCommon, tainted map[ssa.Value]bool) string {
	name, recv, pkg := callInfo(common)
	switch name {
	case "Query", "QueryContext", "QueryRow", "QueryRowContext", "Exec", "ExecContext":
		if !strings.Contains(recv, "database/sql") && !strings.Contains(recv, "pgx") && !strings.Contains(recv, "clickhouse") {
			return ""
		}
		offset := 0
		if !common.IsInvoke() {
			if f := common.StaticCallee(); f != nil && f.Signature != nil && f.Signature.Recv() != nil {
				offset = 1 // receiver входит в Args
			}
		}
		queryIdx := offset
		if strings.HasSuffix(name, "Context") {
			queryIdx++
		}
		if queryIdx < len(common.Args) && tainted[common.Args[queryIdx]] {
			return "sgate-ssa-taint-sql"
		}
		// У pgx сигнатура Query(ctx, sql, args...): суффикса Context нет,
		// поэтому позиция запроса определяется по типу string.
		for _, arg := range common.Args {
			if basic, ok := arg.Type().Underlying().(*types.Basic); ok && basic.Kind() == types.String && tainted[arg] {
				return "sgate-ssa-taint-sql"
			}
		}
	case "Command", "CommandContext":
		if recv == "" && strings.HasSuffix(pkg, "os/exec") {
			for _, arg := range common.Args {
				if tainted[arg] {
					return "sgate-ssa-taint-command"
				}
			}
		}
	case "Open", "OpenFile", "ReadFile", "WriteFile":
		if recv == "" && (strings.HasSuffix(pkg, "os") || strings.HasSuffix(pkg, "io/ioutil")) {
			for _, arg := range common.Args {
				if tainted[arg] {
					return "sgate-ssa-taint-file"
				}
			}
		}
	case "Get", "Post", "NewRequest", "NewRequestWithContext":
		// Только функции пакета net/http. Методы с теми же именами
		// (http.Header.Get — это обычный map-лукап) сюда не относятся.
		if recv != "" || !strings.HasSuffix(pkg, "net/http") {
			return ""
		}
		urlIdx := map[string]int{"Get": 0, "Post": 0, "NewRequest": 1, "NewRequestWithContext": 2}[name]
		if urlIdx < len(common.Args) && tainted[common.Args[urlIdx]] {
			return "sgate-ssa-taint-ssrf"
		}
	}
	return ""
}

func callInfo(common *ssa.CallCommon) (name, recv, pkg string) {
	if common.Method != nil {
		if common.Method.Pkg() != nil {
			pkg = common.Method.Pkg().Path()
		}
		recvType := ""
		if sig := common.Method.Signature(); sig != nil && sig.Recv() != nil {
			recvType = sig.Recv().Type().String()
		}
		return common.Method.Name(), recvType, pkg
	}
	if f, ok := common.Value.(*ssa.Function); ok {
		p := ""
		if f.Pkg != nil {
			p = f.Pkg.Pkg.Path()
		}
		recv := ""
		if f.Signature != nil && f.Signature.Recv() != nil {
			recv = f.Signature.Recv().Type().String()
		}
		return f.Name(), recv, p
	}
	return "", "", ""
}

// isSourceValue — значение получено из пользовательского ввода.
func isSourceValue(v ssa.Value) bool {
	call, ok := v.(*ssa.Call)
	if !ok {
		return false
	}
	name, recv, pkg := callInfo(call.Common())
	switch name {
	case "FormValue", "PostFormValue", "PathValue":
		return true
	case "Get":
		return strings.Contains(recv, "net/url.Values") || strings.Contains(recv, "net/http.Header")
	}
	_ = pkg
	return false
}

func (a *analyzer) report(rule string, call ssa.CallInstruction, fn *ssa.Function) {
	if !a.reachable[fn] && !isHTTPHandler(fn) {
		return
	}
	pos := a.fset.Position(call.Pos())
	if pos.Filename == "" {
		return
	}
	rel, err := filepath.Rel(a.root, pos.Filename)
	if err != nil || strings.HasPrefix(rel, "..") {
		return // stdlib/зависимости вне проекта
	}
	key := rule + "|" + rel + "|" + fmt.Sprint(pos.Line)
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	msg := rule
	for _, r := range Catalog() {
		if r.ID == rule {
			msg = r.Message
			break
		}
	}
	a.findings = append(a.findings, Finding{
		Rule:     rule,
		Severity: severityOf(rule),
		Message:  msg + " (" + fn.Name() + ")",
		File:     rel,
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
