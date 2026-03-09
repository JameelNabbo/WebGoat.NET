package analyzer

import (
	"go/ast"
	"go/token"
	"strings"
)

// TaintSource represents a source of user-controlled data
type TaintSource struct {
	VarName string
	Line    int
	Kind    string // "http_param", "http_body", "http_header", "grpc_request", "stdin", "env", "file"
}

// TaintTracker tracks tainted variables through a function body
type TaintTracker struct {
	tainted   map[string]TaintSource
	sanitized map[string]bool
}

// NewTaintTracker creates a new taint tracker for a function
func NewTaintTracker() *TaintTracker {
	return &TaintTracker{
		tainted:   make(map[string]TaintSource),
		sanitized: make(map[string]bool),
	}
}

// MarkTainted marks a variable as tainted
func (t *TaintTracker) MarkTainted(name string, source TaintSource) {
	t.tainted[name] = source
}

// IsTainted checks if a variable is tainted
func (t *TaintTracker) IsTainted(name string) bool {
	if t.sanitized[name] {
		return false
	}
	_, ok := t.tainted[name]
	return ok
}

// GetSource returns the taint source for a variable
func (t *TaintTracker) GetSource(name string) (TaintSource, bool) {
	s, ok := t.tainted[name]
	return s, ok
}

// MarkSanitized marks a variable as sanitized
func (t *TaintTracker) MarkSanitized(name string) {
	t.sanitized[name] = true
}

// IsExprTainted checks if an expression involves tainted data
func (t *TaintTracker) IsExprTainted(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return t.IsTainted(e.Name)
	case *ast.BinaryExpr:
		return t.IsExprTainted(e.X) || t.IsExprTainted(e.Y)
	case *ast.CallExpr:
		// Check if any argument is tainted
		for _, arg := range e.Args {
			if t.IsExprTainted(arg) {
				return true
			}
		}
		// fmt.Sprintf propagates taint
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "fmt" && (sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Sprint" || sel.Sel.Name == "Fprintf") {
					for _, arg := range e.Args {
						if t.IsExprTainted(arg) {
							return true
						}
					}
				}
				// string() conversion propagates taint
				if sel.Sel.Name == "String" {
					if t.IsExprTainted(sel.X) {
						return true
					}
				}
			}
		}
		// string(x) or []byte(x) propagates taint
		if fn, ok := e.Fun.(*ast.Ident); ok {
			if fn.Name == "string" || fn.Name == "append" {
				for _, arg := range e.Args {
					if t.IsExprTainted(arg) {
						return true
					}
				}
			}
		}
		// Type conversions propagate taint
		if _, ok := e.Fun.(*ast.ArrayType); ok {
			for _, arg := range e.Args {
				if t.IsExprTainted(arg) {
					return true
				}
			}
		}
	case *ast.SelectorExpr:
		return t.IsExprTainted(e.X)
	case *ast.IndexExpr:
		return t.IsExprTainted(e.X)
	case *ast.SliceExpr:
		return t.IsExprTainted(e.X)
	case *ast.StarExpr:
		return t.IsExprTainted(e.X)
	case *ast.UnaryExpr:
		return t.IsExprTainted(e.X)
	case *ast.ParenExpr:
		return t.IsExprTainted(e.X)
	case *ast.TypeAssertExpr:
		return t.IsExprTainted(e.X)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if t.IsExprTainted(elt) {
				return true
			}
		}
	case *ast.KeyValueExpr:
		return t.IsExprTainted(e.Value)
	}
	return false
}

// TrackFunction analyzes a function for taint flow from HTTP sources
func (t *TaintTracker) TrackFunction(fn *ast.FuncDecl, fset *token.FileSet) {
	if fn.Body == nil {
		return
	}

	// Mark HTTP handler parameters as taint sources
	t.markHTTPParams(fn)

	// Walk the function body and propagate taint through assignments
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			t.trackAssignment(stmt)
		case *ast.RangeStmt:
			// Range over tainted collection taints loop vars
			if t.IsExprTainted(stmt.X) {
				if key, ok := stmt.Key.(*ast.Ident); ok {
					t.MarkTainted(key.Name, TaintSource{VarName: key.Name, Kind: "propagated"})
				}
				if val, ok := stmt.Value.(*ast.Ident); ok {
					t.MarkTainted(val.Name, TaintSource{VarName: val.Name, Kind: "propagated"})
				}
			}
		case *ast.ValueSpec:
			// var x = taintedExpr
			if len(stmt.Values) > 0 {
				for i, name := range stmt.Names {
					if i < len(stmt.Values) && t.IsExprTainted(stmt.Values[i]) {
						t.MarkTainted(name.Name, TaintSource{VarName: name.Name, Kind: "propagated"})
					}
				}
			}
		}
		return true
	})
}

// markHTTPParams marks function parameters from HTTP handlers as tainted
func (t *TaintTracker) markHTTPParams(fn *ast.FuncDecl) {
	if fn.Type == nil || fn.Type.Params == nil {
		return
	}

	for _, param := range fn.Type.Params.List {
		paramType := exprToString(param.Type)

		isTaintSource := false
		kind := "http_param"

		// Standard library http.ResponseWriter, *http.Request
		if strings.Contains(paramType, "http.Request") || strings.Contains(paramType, "Request") {
			isTaintSource = true
			kind = "http_request"
		}

		// Gin context
		if strings.Contains(paramType, "gin.Context") || strings.Contains(paramType, "Context") {
			isTaintSource = true
			kind = "gin_context"
		}

		// Echo context
		if strings.Contains(paramType, "echo.Context") {
			isTaintSource = true
			kind = "echo_context"
		}

		// Fiber context
		if strings.Contains(paramType, "fiber.Ctx") {
			isTaintSource = true
			kind = "fiber_context"
		}

		if isTaintSource {
			for _, name := range param.Names {
				t.MarkTainted(name.Name, TaintSource{
					VarName: name.Name,
					Kind:    kind,
				})
			}
		}
	}

	// Walk body to find additional taint sources
	if fn.Body != nil {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range assign.Rhs {
				if t.isHTTPSource(rhs) && i < len(assign.Lhs) {
					if ident, ok := assign.Lhs[i].(*ast.Ident); ok {
						t.MarkTainted(ident.Name, TaintSource{
							VarName: ident.Name,
							Kind:    "http_input",
						})
					}
				}
			}
			return true
		})
	}
}

// isHTTPSource checks if an expression reads from HTTP request
func (t *TaintTracker) isHTTPSource(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		// Check for r.URL.Query(), r.Form, r.Header, etc.
		if sel, ok := expr.(*ast.SelectorExpr); ok {
			name := sel.Sel.Name
			httpFields := []string{"URL", "Body", "Form", "PostForm", "Header", "Host",
				"RemoteAddr", "RequestURI", "Referer", "UserAgent"}
			for _, f := range httpFields {
				if name == f {
					if t.IsExprTainted(sel.X) {
						return true
					}
				}
			}
		}
		return false
	}

	funcName := getFuncName(call)

	// HTTP request methods
	httpSources := []string{
		"FormValue", "PostFormValue", "Query", "Param", "GetQuery",
		"BindJSON", "ShouldBindJSON", "Bind", "ShouldBind",
		"QueryParam", "FormValue", "Cookie", "GetHeader",
		"ReadAll", "ReadBody", "Params", "QueryString",
		"Get", "PostForm", "DefaultQuery", "DefaultPostForm",
		"GetString", "GetInt", "GetBool",
	}

	for _, src := range httpSources {
		if strings.HasSuffix(funcName, "."+src) || funcName == src {
			return true
		}
	}

	// ioutil.ReadAll(r.Body) or io.ReadAll(r.Body)
	if strings.HasSuffix(funcName, "ReadAll") || funcName == "ReadAll" {
		for _, arg := range call.Args {
			if t.IsExprTainted(arg) {
				return true
			}
		}
	}

	// json.NewDecoder(r.Body).Decode()
	if strings.HasSuffix(funcName, "Decode") || strings.HasSuffix(funcName, "Unmarshal") {
		for _, arg := range call.Args {
			if t.IsExprTainted(arg) {
				return true
			}
		}
	}

	// os.Getenv
	if funcName == "os.Getenv" || funcName == "os.LookupEnv" {
		return true
	}

	// Stdin
	if funcName == "bufio.NewReader" || funcName == "bufio.NewScanner" {
		return true
	}

	return false
}

// trackAssignment propagates taint through assignments
func (t *TaintTracker) trackAssignment(stmt *ast.AssignStmt) {
	for i, rhs := range stmt.Rhs {
		if i >= len(stmt.Lhs) {
			break
		}

		lhs, ok := stmt.Lhs[i].(*ast.Ident)
		if !ok {
			continue
		}

		if t.IsExprTainted(rhs) || t.isHTTPSource(rhs) {
			t.MarkTainted(lhs.Name, TaintSource{
				VarName: lhs.Name,
				Kind:    "propagated",
			})
		}
	}
}
