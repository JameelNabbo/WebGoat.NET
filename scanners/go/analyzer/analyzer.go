package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"

	"gosastscanner/models"
)

// Analyzer is the main AST-based Go security scanner
type Analyzer struct {
	fset    *token.FileSet
	files   map[string]*ast.File
	sources map[string]string
	vulns   []models.Vulnerability
	mu      sync.Mutex
	idCount int

	// Cross-file context
	imports   map[string]map[string]string // file -> alias -> path
	functions map[string][]*ast.FuncDecl   // file -> funcs
	globals   map[string][]ast.Decl        // file -> global decls
}

// New creates a new Analyzer
func New() *Analyzer {
	return &Analyzer{
		fset:      token.NewFileSet(),
		files:     make(map[string]*ast.File),
		sources:   make(map[string]string),
		imports:   make(map[string]map[string]string),
		functions: make(map[string][]*ast.FuncDecl),
		globals:   make(map[string][]ast.Decl),
	}
}

// ParseFiles parses all provided Go source files
func (a *Analyzer) ParseFiles(files map[string]string) []string {
	var errs []string
	for path, content := range files {
		if !strings.HasSuffix(path, ".go") {
			continue
		}
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		a.sources[path] = content
		f, err := parser.ParseFile(a.fset, path, content, parser.ParseComments)
		if err != nil {
			errs = append(errs, fmt.Sprintf("parse error in %s: %v", path, err))
			// Try to parse with error recovery
			f, _ = parser.ParseFile(a.fset, path, content, parser.ParseComments|parser.AllErrors)
			if f == nil {
				continue
			}
		}
		a.files[path] = f
		a.extractImports(path, f)
		a.extractFunctions(path, f)
	}
	return errs
}

// extractImports maps import aliases to import paths for a file
func (a *Analyzer) extractImports(path string, f *ast.File) {
	a.imports[path] = make(map[string]string)
	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, "\"")
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			parts := strings.Split(importPath, "/")
			alias = parts[len(parts)-1]
		}
		a.imports[path][alias] = importPath
	}
}

// extractFunctions collects all function declarations
func (a *Analyzer) extractFunctions(path string, f *ast.File) {
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			a.functions[path] = append(a.functions[path], fn)
		}
	}
}

// Analyze runs all security rules against parsed files
func (a *Analyzer) Analyze() []models.Vulnerability {
	for path, f := range a.files {
		ctx := &FileContext{
			Path:    path,
			File:    f,
			Fset:    a.fset,
			Source:  a.sources[path],
			Imports: a.imports[path],
		}

		// Run all rule checks
		a.checkSQLInjection(ctx)
		a.checkCommandInjection(ctx)
		a.checkPathTraversal(ctx)
		a.checkXSS(ctx)
		a.checkSSRF(ctx)
		a.checkHardcodedSecrets(ctx)
		a.checkWeakCrypto(ctx)
		a.checkInsecureRandom(ctx)
		a.checkRaceConditions(ctx)
		a.checkResourceLeaks(ctx)
		a.checkErrorHandling(ctx)
		a.checkIntegerOverflow(ctx)
		a.checkNilPointerDeref(ctx)
		a.checkInsecureTLS(ctx)
		a.checkCORSMisconfig(ctx)
		a.checkMissingAuth(ctx)
		a.checkInfoDisclosure(ctx)
		a.checkTemplateInjection(ctx)
		a.checkGinSpecific(ctx)
		a.checkEchoSpecific(ctx)
		a.checkFiberSpecific(ctx)
		a.checkGRPCSpecific(ctx)
		a.checkUnsafePackage(ctx)
		a.checkGoroutineLeaks(ctx)
		a.checkJWTIssues(ctx)
		a.checkOpenRedirect(ctx)
		a.checkFileUpload(ctx)
		a.checkLoggingSensitiveData(ctx)
		a.checkMassAssignment(ctx)
		a.checkTimingAttacks(ctx)
	}
	return a.vulns
}

// FileContext holds per-file analysis context
type FileContext struct {
	Path    string
	File    *ast.File
	Fset    *token.FileSet
	Source  string
	Imports map[string]string
}

// HasImport checks if a file imports a specific package
func (fc *FileContext) HasImport(pkg string) bool {
	for _, imp := range fc.Imports {
		if imp == pkg || strings.HasSuffix(imp, "/"+pkg) {
			return true
		}
	}
	return false
}

// GetImportAlias returns the alias used for an import
func (fc *FileContext) GetImportAlias(pkg string) string {
	for alias, imp := range fc.Imports {
		if imp == pkg || strings.HasSuffix(imp, "/"+pkg) {
			return alias
		}
	}
	return ""
}

// addVuln adds a vulnerability finding (thread-safe)
func (a *Analyzer) addVuln(v models.Vulnerability) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.idCount++
	v.ID = fmt.Sprintf("GO-%04d", a.idCount)
	a.vulns = append(a.vulns, v)
}

// getSnippet extracts source code around a position
func (a *Analyzer) getSnippet(ctx *FileContext, node ast.Node) string {
	if node == nil {
		return ""
	}
	start := a.fset.Position(node.Pos())
	end := a.fset.Position(node.End())
	lines := strings.Split(ctx.Source, "\n")
	startLine := start.Line - 1
	endLine := end.Line
	if startLine < 0 {
		startLine = 0
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}
	// Context: 1 line before, up to 2 after
	if startLine > 0 {
		startLine--
	}
	if endLine < len(lines)-1 {
		endLine++
	}
	if endLine-startLine > 6 {
		endLine = startLine + 6
	}
	return strings.Join(lines[startLine:endLine], "\n")
}

// getLine returns the line number of an AST node
func (a *Analyzer) getLine(node ast.Node) int {
	return a.fset.Position(node.Pos()).Line
}

// getEndLine returns the end line number
func (a *Analyzer) getEndLine(node ast.Node) int {
	return a.fset.Position(node.End()).Line
}

// Helper: check if a node is a call to package.Function
func isCallTo(call *ast.CallExpr, pkg, fn string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == pkg && sel.Sel.Name == fn
}

// Helper: check if a selector matches package.Field
func isSelectorExpr(expr ast.Expr, pkg, field string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == pkg && sel.Sel.Name == field
}

// Helper: check if expression involves string concatenation or fmt.Sprintf
func involvesStringConcat(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return true
		}
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "fmt" && (sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Sprint") {
					return true
				}
				if ident.Name == "strings" && (sel.Sel.Name == "Join" || sel.Sel.Name == "Replace") {
					return true
				}
			}
		}
	}
	return false
}

// Helper: check if expression is a string literal
func isStringLit(expr ast.Expr) bool {
	if lit, ok := expr.(*ast.BasicLit); ok {
		return lit.Kind == token.STRING
	}
	return false
}

// Helper: walk all statements in a function body
func walkFunc(fn *ast.FuncDecl, visitor func(ast.Node) bool) {
	if fn.Body == nil {
		return
	}
	ast.Inspect(fn.Body, visitor)
}

// Helper: check if a string looks like it contains format directives
func hasFormatDirective(s string) bool {
	return strings.Contains(s, "%s") || strings.Contains(s, "%v") || strings.Contains(s, "%d")
}

// Helper: get function name from a call expr
func getFuncName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	}
	return ""
}

// Helper: exprToString gives a rough string representation
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	case *ast.BasicLit:
		return e.Value
	case *ast.CallExpr:
		return getFuncName(e) + "(...)"
	case *ast.BinaryExpr:
		return exprToString(e.X) + " " + e.Op.String() + " " + exprToString(e.Y)
	case *ast.IndexExpr:
		return exprToString(e.X) + "[...]"
	case *ast.StarExpr:
		return "*" + exprToString(e.X)
	case *ast.UnaryExpr:
		return e.Op.String() + exprToString(e.X)
	}
	return "<?>"
}
