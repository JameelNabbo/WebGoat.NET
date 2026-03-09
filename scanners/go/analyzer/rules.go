package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"gosastscanner/models"
)

// =============================================================================
// 1. SQL Injection
// =============================================================================

func (a *Analyzer) checkSQLInjection(ctx *FileContext) {
	if !ctx.HasImport("database/sql") && !ctx.HasImport("gorm.io/gorm") &&
		!ctx.HasImport("github.com/jinzhu/gorm") && !ctx.HasImport("github.com/jmoiron/sqlx") &&
		!ctx.HasImport("github.com/go-pg/pg") {
		return
	}

	dangerousFuncs := []string{"Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext",
		"Raw", "Where", "Having", "Order", "Group", "Select", "Joins",
		"Rebind", "MustExec", "NamedExec", "Get"}

	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			for _, dangerous := range dangerousFuncs {
				if strings.HasSuffix(funcName, "."+dangerous) && len(call.Args) > 0 {
					argToCheck := call.Args[0]
					// For context variants, check second arg
					if strings.HasSuffix(dangerous, "Context") && len(call.Args) > 1 {
						argToCheck = call.Args[1]
					}

					if involvesStringConcat(argToCheck) || tracker.IsExprTainted(argToCheck) {
						if !isParameterizedQuery(argToCheck) {
							a.addVuln(models.Vulnerability{
								Title:       "SQL Injection",
								Description: "SQL query built using string concatenation or user input: " + exprToString(argToCheck),
								Severity:    models.SeverityCritical,
								Confidence:  models.ConfidenceHigh,
								Category:    "SQL Injection",
								CWE:         "CWE-89",
								OWASP:       "A03:2021",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(call),
								EndLine:     a.getEndLine(call),
								Snippet:     a.getSnippet(ctx, call),
								Remediation: "Use parameterized queries with placeholders ($1, ?, @param). Example: db.Query(\"SELECT * FROM users WHERE id = $1\", id)",
							})
						}
					}
				}
			}
			return true
		})
	}
}

func isParameterizedQuery(expr ast.Expr) bool {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		val := lit.Value
		return strings.Contains(val, "$") || strings.Contains(val, "?") || strings.Contains(val, "@")
	}
	return false
}

// =============================================================================
// 2. Command Injection
// =============================================================================

func (a *Analyzer) checkCommandInjection(ctx *FileContext) {
	if !ctx.HasImport("os/exec") && !ctx.HasImport("os") && !ctx.HasImport("syscall") {
		return
	}

	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)

			if funcName == "exec.Command" || funcName == "exec.CommandContext" {
				for _, arg := range call.Args {
					if tracker.IsExprTainted(arg) || involvesStringConcat(arg) {
						a.addVuln(models.Vulnerability{
							Title:       "Command Injection",
							Description: "OS command constructed with user-controlled input: " + exprToString(arg),
							Severity:    models.SeverityCritical,
							Confidence:  models.ConfidenceHigh,
							Category:    "Command Injection",
							CWE:         "CWE-78",
							OWASP:       "A03:2021",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Avoid passing user input to exec.Command. Use allowlists for permitted commands and validate/sanitize arguments.",
						})
						break
					}
				}
			}

			if funcName == "os.StartProcess" {
				for _, arg := range call.Args {
					if tracker.IsExprTainted(arg) {
						a.addVuln(models.Vulnerability{
							Title:       "Command Injection via os.StartProcess",
							Description: "Process started with potentially user-controlled arguments",
							Severity:    models.SeverityCritical,
							Confidence:  models.ConfidenceMedium,
							Category:    "Command Injection",
							CWE:         "CWE-78",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Validate and sanitize all process arguments. Use exec.Command with individual arguments instead of shell interpolation.",
						})
						break
					}
				}
			}

			if funcName == "syscall.Exec" || funcName == "syscall.ForkExec" {
				a.addVuln(models.Vulnerability{
					Title:       "Low-level Process Execution via syscall",
					Description: "Direct syscall used for process execution, bypassing higher-level safety checks",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceMedium,
					Category:    "Command Injection",
					CWE:         "CWE-78",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(call),
					EndLine:     a.getEndLine(call),
					Snippet:     a.getSnippet(ctx, call),
					Remediation: "Use exec.Command instead of syscall.Exec for better input validation support.",
				})
			}

			return true
		})
	}
}

// =============================================================================
// 3. Path Traversal
// =============================================================================

func (a *Analyzer) checkPathTraversal(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			fileOps := []string{
				"os.Open", "os.OpenFile", "os.Create", "os.ReadFile", "os.WriteFile",
				"os.Remove", "os.RemoveAll", "os.Mkdir", "os.MkdirAll",
				"os.Stat", "os.Lstat", "os.Rename",
				"ioutil.ReadFile", "ioutil.WriteFile", "ioutil.ReadDir",
				"filepath.Join", "filepath.Clean",
				"http.ServeFile", "http.Dir",
			}

			for _, op := range fileOps {
				if funcName == op && len(call.Args) > 0 {
					for _, arg := range call.Args {
						if tracker.IsExprTainted(arg) {
							if funcName == "filepath.Clean" {
								tracker.MarkSanitized(exprToString(arg))
								continue
							}
							a.addVuln(models.Vulnerability{
								Title:       "Path Traversal",
								Description: "File operation uses user-controlled path: " + funcName + "(" + exprToString(arg) + ")",
								Severity:    models.SeverityHigh,
								Confidence:  models.ConfidenceHigh,
								Category:    "Path Traversal",
								CWE:         "CWE-22",
								OWASP:       "A01:2021",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(call),
								EndLine:     a.getEndLine(call),
								Snippet:     a.getSnippet(ctx, call),
								Remediation: "Validate that the resolved path stays within the expected base directory. Use filepath.Rel() and check the result does not start with '..'",
							})
							break
						}
					}
				}
			}

			return true
		})
	}
}

// =============================================================================
// 4. XSS (Cross-Site Scripting)
// =============================================================================

func (a *Analyzer) checkXSS(ctx *FileContext) {
	// text/template without html/template
	if ctx.HasImport("text/template") && !ctx.HasImport("html/template") {
		ast.Inspect(ctx.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			funcName := getFuncName(call)
			if strings.Contains(funcName, "template.New") || strings.Contains(funcName, "template.Must") ||
				strings.Contains(funcName, "template.Parse") {
				a.addVuln(models.Vulnerability{
					Title:       "XSS - text/template Used Instead of html/template",
					Description: "text/template does not auto-escape HTML output. Use html/template for web responses.",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    "Cross-Site Scripting",
					CWE:         "CWE-79",
					OWASP:       "A03:2021",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(call),
					EndLine:     a.getEndLine(call),
					Snippet:     a.getSnippet(ctx, call),
					Remediation: "Replace text/template with html/template which auto-escapes HTML, JS, CSS, and URL contexts.",
				})
			}
			return true
		})
	}

	// Direct write of user input to response
	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			funcName := getFuncName(call)

			writeFuncs := []string{"Write", "WriteString"}
			for _, wf := range writeFuncs {
				if strings.HasSuffix(funcName, "."+wf) {
					for _, arg := range call.Args {
						if tracker.IsExprTainted(arg) {
							a.addVuln(models.Vulnerability{
								Title:       "Potential XSS - Unescaped User Input in Response",
								Description: "User-controlled data written directly to HTTP response without escaping",
								Severity:    models.SeverityHigh,
								Confidence:  models.ConfidenceMedium,
								Category:    "Cross-Site Scripting",
								CWE:         "CWE-79",
								OWASP:       "A03:2021",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(call),
								EndLine:     a.getEndLine(call),
								Snippet:     a.getSnippet(ctx, call),
								Remediation: "Use html/template for HTML output or html.EscapeString() for plain text responses.",
							})
						}
					}
				}
			}

			if funcName == "fmt.Fprintf" || funcName == "fmt.Fprint" {
				if len(call.Args) > 1 {
					for _, arg := range call.Args[1:] {
						if tracker.IsExprTainted(arg) {
							a.addVuln(models.Vulnerability{
								Title:       "Potential XSS - User Input in fmt.Fprintf Response",
								Description: "User data passed to fmt.Fprintf which may write to HTTP response",
								Severity:    models.SeverityMedium,
								Confidence:  models.ConfidenceMedium,
								Category:    "Cross-Site Scripting",
								CWE:         "CWE-79",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(call),
								EndLine:     a.getEndLine(call),
								Snippet:     a.getSnippet(ctx, call),
								Remediation: "Escape user input before writing to HTTP response. Use html.EscapeString() or html/template.",
							})
						}
					}
				}
			}

			return true
		})
	}
}

// =============================================================================
// 5. SSRF (Server-Side Request Forgery)
// =============================================================================

func (a *Analyzer) checkSSRF(ctx *FileContext) {
	if !ctx.HasImport("net/http") && !ctx.HasImport("net/url") {
		return
	}

	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			ssrfFuncs := []string{"http.Get", "http.Post", "http.PostForm", "http.Head",
				"http.NewRequest", "http.NewRequestWithContext"}

			for _, sf := range ssrfFuncs {
				if funcName == sf && len(call.Args) > 0 {
					urlArg := call.Args[0]
					if strings.Contains(sf, "NewRequest") && len(call.Args) > 1 {
						urlArg = call.Args[1]
					}
					if tracker.IsExprTainted(urlArg) || involvesStringConcat(urlArg) {
						a.addVuln(models.Vulnerability{
							Title:       "Server-Side Request Forgery (SSRF)",
							Description: "HTTP request made with user-controlled URL: " + exprToString(urlArg),
							Severity:    models.SeverityHigh,
							Confidence:  models.ConfidenceHigh,
							Category:    "SSRF",
							CWE:         "CWE-918",
							OWASP:       "A10:2021",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Validate and restrict URLs to an allowlist of safe domains. Block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).",
						})
					}
				}
			}

			return true
		})
	}
}

// =============================================================================
// 6. Hardcoded Secrets
// =============================================================================

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*"[^"]{4,}"`),
	regexp.MustCompile(`(?i)(secret|token|api[_-]?key|apikey)\s*[:=]\s*"[^"]{8,}"`),
	regexp.MustCompile(`(?i)(access[_-]?key|private[_-]?key)\s*[:=]\s*"[^"]{8,}"`),
	regexp.MustCompile(`(?i)authorization\s*[:=]\s*"(Bearer|Basic)\s+[^"]+"`),
	regexp.MustCompile(`(?i)(aws|gcp|azure|github|gitlab|slack).*[:=]\s*"[a-zA-Z0-9/+=]{16,}"`),
	regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)connection[_-]?string\s*[:=]\s*"[^"]{10,}"`),
	regexp.MustCompile(`(?i)database[_-]?url\s*[:=]\s*"[^"]{10,}"`),
}

func (a *Analyzer) checkHardcodedSecrets(ctx *FileContext) {
	lines := strings.Split(ctx.Source, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		for _, pattern := range secretPatterns {
			if pattern.MatchString(line) {
				lower := strings.ToLower(line)
				if strings.Contains(lower, "example") || strings.Contains(lower, "placeholder") ||
					strings.Contains(lower, "changeme") || strings.Contains(lower, "xxx") ||
					strings.Contains(lower, "todo") || strings.Contains(lower, "fixme") ||
					strings.Contains(lower, "your_") || strings.Contains(lower, "<your") {
					continue
				}

				snippetStart := i
				snippetEnd := i + 1
				if snippetStart > 0 {
					snippetStart--
				}
				if snippetEnd < len(lines) {
					snippetEnd++
				}
				snippet := strings.Join(lines[snippetStart:snippetEnd], "\n")

				a.addVuln(models.Vulnerability{
					Title:       "Hardcoded Secret",
					Description: "Potential hardcoded credential or secret found in source code",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceMedium,
					Category:    "Hardcoded Secrets",
					CWE:         "CWE-798",
					OWASP:       "A07:2021",
					FilePath:    ctx.Path,
					StartLine:   i + 1,
					EndLine:     i + 1,
					Snippet:     snippet,
					Remediation: "Use environment variables, secret management services (Vault, AWS Secrets Manager), or configuration files excluded from version control.",
				})
				break
			}
		}
	}

	// Check const blocks for secrets
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		genDecl, ok := n.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			return true
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				lower := strings.ToLower(name.Name)
				if strings.Contains(lower, "password") || strings.Contains(lower, "secret") ||
					strings.Contains(lower, "apikey") || strings.Contains(lower, "token") ||
					strings.Contains(lower, "private") {
					if len(vs.Values) > 0 {
						if lit, ok := vs.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							val := strings.Trim(lit.Value, "\"`")
							if len(val) > 3 {
								a.addVuln(models.Vulnerability{
									Title:       "Hardcoded Secret in Constant",
									Description: "Constant '" + name.Name + "' contains a hardcoded secret value",
									Severity:    models.SeverityHigh,
									Confidence:  models.ConfidenceHigh,
									Category:    "Hardcoded Secrets",
									CWE:         "CWE-798",
									FilePath:    ctx.Path,
									StartLine:   a.getLine(vs),
									EndLine:     a.getEndLine(vs),
									Snippet:     a.getSnippet(ctx, vs),
									Remediation: "Move secrets to environment variables or a secret management solution.",
								})
							}
						}
					}
				}
			}
		}
		return true
	})
}

// =============================================================================
// 7. Weak Cryptography
// =============================================================================

func (a *Analyzer) checkWeakCrypto(ctx *FileContext) {
	weakImports := map[string]string{
		"crypto/md5":  "MD5 is cryptographically broken and should not be used for security purposes",
		"crypto/sha1": "SHA1 is deprecated for security use due to collision attacks",
		"crypto/des":  "DES/3DES is deprecated due to small block size and key length",
		"crypto/rc4":  "RC4 is broken and should not be used",
	}

	for _, imp := range ctx.File.Imports {
		importPath := strings.Trim(imp.Path.Value, "\"")
		if desc, ok := weakImports[importPath]; ok {
			a.addVuln(models.Vulnerability{
				Title:       "Weak Cryptographic Algorithm",
				Description: desc + " (import: " + importPath + ")",
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				Category:    "Weak Cryptography",
				CWE:         "CWE-327",
				OWASP:       "A02:2021",
				FilePath:    ctx.Path,
				StartLine:   a.getLine(imp),
				EndLine:     a.getEndLine(imp),
				Snippet:     a.getSnippet(ctx, imp),
				Remediation: "Use SHA-256/SHA-512 for hashing, AES-GCM for encryption. For passwords, use bcrypt/scrypt/argon2.",
			})
		}
	}

	// Check for weak RSA key sizes
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if getFuncName(call) == "rsa.GenerateKey" && len(call.Args) >= 2 {
				if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.INT {
					keySize := lit.Value
					if keySize == "512" || keySize == "1024" {
						a.addVuln(models.Vulnerability{
							Title:       "Weak RSA Key Size",
							Description: "RSA key size " + keySize + " bits is too small. Minimum recommended: 2048 bits.",
							Severity:    models.SeverityHigh,
							Confidence:  models.ConfidenceHigh,
							Category:    "Weak Cryptography",
							CWE:         "CWE-326",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Use at least 2048-bit RSA keys, preferably 4096-bit. Consider using Ed25519 for better performance.",
						})
					}
				}
			}
			return true
		})
	}
}

// =============================================================================
// 8. Insecure Random
// =============================================================================

func (a *Analyzer) checkInsecureRandom(ctx *FileContext) {
	if !ctx.HasImport("math/rand") {
		return
	}

	mathRandAlias := ctx.GetImportAlias("math/rand")
	if mathRandAlias == "" {
		mathRandAlias = "rand"
	}

	hasCryptoRand := ctx.HasImport("crypto/rand")

	ast.Inspect(ctx.File, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		funcName := getFuncName(call)
		if strings.HasPrefix(funcName, mathRandAlias+".") {
			confidence := models.ConfidenceMedium
			if hasCryptoRand {
				confidence = models.ConfidenceLow
			}

			a.addVuln(models.Vulnerability{
				Title:       "Insecure Random Number Generator",
				Description: "math/rand is not cryptographically secure. Used: " + funcName,
				Severity:    models.SeverityMedium,
				Confidence:  confidence,
				Category:    "Insecure Randomness",
				CWE:         "CWE-330",
				OWASP:       "A02:2021",
				FilePath:    ctx.Path,
				StartLine:   a.getLine(call),
				EndLine:     a.getEndLine(call),
				Snippet:     a.getSnippet(ctx, call),
				Remediation: "Use crypto/rand for security-sensitive random values (tokens, keys, nonces). math/rand is only suitable for non-security purposes.",
			})
		}
		return true
	})
}

// =============================================================================
// 9. Race Conditions
// =============================================================================

func (a *Analyzer) checkRaceConditions(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		if fn.Body == nil {
			continue
		}

		var hasGoStmt bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				hasGoStmt = true
				return false
			}
			return true
		})

		if !hasGoStmt {
			continue
		}

		// Check for shared map access without sync
		hasMutex := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if ok {
				name := getFuncName(call)
				if strings.Contains(name, ".Lock") || strings.Contains(name, ".RLock") ||
					strings.Contains(name, "sync.") {
					hasMutex = true
				}
			}
			return true
		})

		if !hasMutex {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				goStmt, ok := n.(*ast.GoStmt)
				if !ok {
					return true
				}

				ast.Inspect(goStmt.Call, func(inner ast.Node) bool {
					if assign, ok := inner.(*ast.AssignStmt); ok {
						for _, lhs := range assign.Lhs {
							if _, ok := lhs.(*ast.IndexExpr); ok {
								a.addVuln(models.Vulnerability{
									Title:       "Race Condition - Unprotected Map Access",
									Description: "Map accessed in goroutine without mutex protection. Concurrent map read/write causes panic in Go.",
									Severity:    models.SeverityHigh,
									Confidence:  models.ConfidenceMedium,
									Category:    "Race Condition",
									CWE:         "CWE-362",
									FilePath:    ctx.Path,
									StartLine:   a.getLine(goStmt),
									EndLine:     a.getEndLine(goStmt),
									Snippet:     a.getSnippet(ctx, goStmt),
									Remediation: "Use sync.Mutex, sync.RWMutex, or sync.Map for concurrent map access.",
								})
								return false
							}
						}
					}
					return true
				})
				return true
			})
		}

		// Check for loop variable capture in goroutines
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			rangeStmt, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}

			ast.Inspect(rangeStmt.Body, func(inner ast.Node) bool {
				goStmt, ok := inner.(*ast.GoStmt)
				if !ok {
					return true
				}

				var rangeVarNames []string
				if key, ok := rangeStmt.Key.(*ast.Ident); ok {
					rangeVarNames = append(rangeVarNames, key.Name)
				}
				if val, ok := rangeStmt.Value.(*ast.Ident); ok {
					rangeVarNames = append(rangeVarNames, val.Name)
				}

				ast.Inspect(goStmt.Call, func(innermost ast.Node) bool {
					if ident, ok := innermost.(*ast.Ident); ok {
						for _, rvn := range rangeVarNames {
							if ident.Name == rvn {
								a.addVuln(models.Vulnerability{
									Title:       "Race Condition - Range Variable Captured by Goroutine",
									Description: "Range variable '" + ident.Name + "' captured by goroutine closure",
									Severity:    models.SeverityHigh,
									Confidence:  models.ConfidenceHigh,
									Category:    "Race Condition",
									CWE:         "CWE-362",
									FilePath:    ctx.Path,
									StartLine:   a.getLine(goStmt),
									EndLine:     a.getEndLine(goStmt),
									Snippet:     a.getSnippet(ctx, goStmt),
									Remediation: "Pass the range variable as a goroutine function parameter: go func(v Type) { ... }(v)",
								})
								return false
							}
						}
					}
					return true
				})
				return true
			})
			return true
		})
	}
}

// =============================================================================
// 10. Resource Leaks
// =============================================================================

func (a *Analyzer) checkResourceLeaks(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		if fn.Body == nil {
			continue
		}

		walkFunc(fn, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}

			for _, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}

				funcName := getFuncName(call)

				// HTTP response body leak
				httpFuncs := []string{"http.Get", "http.Post", "http.Head", "http.PostForm", "http.Do"}
				for _, hf := range httpFuncs {
					if funcName == hf || strings.HasSuffix(funcName, ".Do") {
						if !hasDeferClose(fn.Body, assign) {
							a.addVuln(models.Vulnerability{
								Title:       "Resource Leak - HTTP Response Body Not Closed",
								Description: "HTTP response body must be closed with defer resp.Body.Close()",
								Severity:    models.SeverityMedium,
								Confidence:  models.ConfidenceMedium,
								Category:    "Resource Leak",
								CWE:         "CWE-772",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(assign),
								EndLine:     a.getEndLine(assign),
								Snippet:     a.getSnippet(ctx, assign),
								Remediation: "Always defer resp.Body.Close() after checking the error.",
							})
						}
						break
					}
				}

				// File handle leak
				fileFuncs := []string{"os.Open", "os.OpenFile", "os.Create", "os.CreateTemp"}
				for _, ff := range fileFuncs {
					if funcName == ff {
						if !hasDeferClose(fn.Body, assign) {
							a.addVuln(models.Vulnerability{
								Title:       "Resource Leak - File Handle Not Closed",
								Description: "File opened with " + funcName + " but no defer f.Close() found",
								Severity:    models.SeverityMedium,
								Confidence:  models.ConfidenceMedium,
								Category:    "Resource Leak",
								CWE:         "CWE-772",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(assign),
								EndLine:     a.getEndLine(assign),
								Snippet:     a.getSnippet(ctx, assign),
								Remediation: "Always defer file.Close() after opening.",
							})
						}
					}
				}

				// DB connection leak
				dbFuncs := []string{"sql.Open", "sqlx.Open", "sqlx.Connect", "gorm.Open"}
				for _, df := range dbFuncs {
					if funcName == df {
						if !hasDeferClose(fn.Body, assign) {
							a.addVuln(models.Vulnerability{
								Title:       "Resource Leak - Database Connection Not Closed",
								Description: "Database connection opened but no defer db.Close() found",
								Severity:    models.SeverityMedium,
								Confidence:  models.ConfidenceLow,
								Category:    "Resource Leak",
								CWE:         "CWE-772",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(assign),
								EndLine:     a.getEndLine(assign),
								Snippet:     a.getSnippet(ctx, assign),
								Remediation: "Ensure database connections are closed.",
							})
						}
					}
				}
			}
			return true
		})
	}
}

func hasDeferClose(body *ast.BlockStmt, assign *ast.AssignStmt) bool {
	assignLine := assign.Pos()
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		deferStmt, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if deferStmt.Pos() > assignLine {
			callName := getFuncName(deferStmt.Call)
			if strings.HasSuffix(callName, ".Close") || strings.HasSuffix(callName, "Close") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// =============================================================================
// 11. Error Handling
// =============================================================================

func (a *Analyzer) checkErrorHandling(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}

			// Check for _ = someFunc() where last return is error
			if len(assign.Lhs) >= 2 {
				lastLhs := assign.Lhs[len(assign.Lhs)-1]
				if ident, ok := lastLhs.(*ast.Ident); ok && ident.Name == "_" {
					if len(assign.Rhs) > 0 {
						if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
							funcName := getFuncName(call)
							if strings.HasPrefix(funcName, "fmt.Print") || strings.HasPrefix(funcName, "fmt.Fprint") {
								return true
							}
							a.addVuln(models.Vulnerability{
								Title:       "Ignored Error",
								Description: "Error return from " + funcName + " is discarded with blank identifier",
								Severity:    models.SeverityMedium,
								Confidence:  models.ConfidenceMedium,
								Category:    "Error Handling",
								CWE:         "CWE-391",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(assign),
								EndLine:     a.getEndLine(assign),
								Snippet:     a.getSnippet(ctx, assign),
								Remediation: "Always handle errors. At minimum, log the error.",
							})
						}
					}
				}
			}

			// Single return value discarded: _ = f.Close()
			if len(assign.Lhs) == 1 {
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name == "_" {
					if len(assign.Rhs) > 0 {
						if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
							funcName := getFuncName(call)
							closeFuncs := []string{"Close", "Flush", "Sync", "Write", "WriteString"}
							for _, cf := range closeFuncs {
								if strings.HasSuffix(funcName, "."+cf) {
									a.addVuln(models.Vulnerability{
										Title:       "Ignored Error from " + cf,
										Description: "Error from " + funcName + " is silently ignored",
										Severity:    models.SeverityLow,
										Confidence:  models.ConfidenceMedium,
										Category:    "Error Handling",
										CWE:         "CWE-391",
										FilePath:    ctx.Path,
										StartLine:   a.getLine(assign),
										EndLine:     a.getEndLine(assign),
										Snippet:     a.getSnippet(ctx, assign),
										Remediation: "Check and handle the error return value.",
									})
								}
							}
						}
					}
				}
			}

			return true
		})

		// Check for panic() in non-main functions
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "panic" {
				if fn.Name != nil && fn.Name.Name != "main" && fn.Name.Name != "init" {
					a.addVuln(models.Vulnerability{
						Title:       "Panic in Non-Main Function",
						Description: "panic() used in function '" + fn.Name.Name + "'. Panics crash the entire application.",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceMedium,
						Category:    "Error Handling",
						CWE:         "CWE-755",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(call),
						EndLine:     a.getEndLine(call),
						Snippet:     a.getSnippet(ctx, call),
						Remediation: "Return errors instead of panicking. Reserve panic() for truly unrecoverable situations.",
					})
				}
			}
			return true
		})
	}
}

// =============================================================================
// 12. Integer Overflow
// =============================================================================

func (a *Analyzer) checkIntegerOverflow(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			if fnIdent, ok := call.Fun.(*ast.Ident); ok {
				unsafeConversions := map[string]string{
					"int32":  "int64 or uint64 value may overflow int32",
					"int16":  "larger integer value may overflow int16",
					"int8":   "larger integer value may overflow int8",
					"uint8":  "larger integer value may overflow uint8",
					"uint16": "larger integer value may overflow uint16",
					"uint32": "int64 or uint64 value may overflow uint32",
				}

				if desc, ok := unsafeConversions[fnIdent.Name]; ok {
					if len(call.Args) > 0 {
						a.addVuln(models.Vulnerability{
							Title:       "Potential Integer Overflow",
							Description: "Type conversion to " + fnIdent.Name + ": " + desc,
							Severity:    models.SeverityMedium,
							Confidence:  models.ConfidenceLow,
							Category:    "Integer Overflow",
							CWE:         "CWE-190",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Check bounds before narrowing integer conversions.",
						})
					}
				}
			}

			return true
		})
	}
}

// =============================================================================
// 13. Nil Pointer Dereference
// =============================================================================

func (a *Analyzer) checkNilPointerDeref(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}

			for _, rhs := range assign.Rhs {
				if _, ok := rhs.(*ast.TypeAssertExpr); ok {
					if len(assign.Lhs) == 1 {
						a.addVuln(models.Vulnerability{
							Title:       "Unchecked Type Assertion",
							Description: "Single-value type assertion will panic if the type does not match",
							Severity:    models.SeverityMedium,
							Confidence:  models.ConfidenceHigh,
							Category:    "Nil Pointer Dereference",
							CWE:         "CWE-476",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(assign),
							EndLine:     a.getEndLine(assign),
							Snippet:     a.getSnippet(ctx, assign),
							Remediation: "Use two-value type assertion: val, ok := x.(Type); if !ok { handle error }",
						})
					}
				}
			}

			return true
		})

		// Check for nil map initialization
		walkFunc(fn, func(n ast.Node) bool {
			decl, ok := n.(*ast.DeclStmt)
			if !ok {
				return true
			}
			genDecl, ok := decl.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range genDecl.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if _, ok := vs.Type.(*ast.MapType); ok {
					if len(vs.Values) == 0 {
						for _, name := range vs.Names {
							a.addVuln(models.Vulnerability{
								Title:       "Potential Nil Map Assignment",
								Description: "Map variable '" + name.Name + "' declared without initialization. Writing to nil map causes panic.",
								Severity:    models.SeverityMedium,
								Confidence:  models.ConfidenceLow,
								Category:    "Nil Pointer Dereference",
								CWE:         "CWE-476",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(vs),
								EndLine:     a.getEndLine(vs),
								Snippet:     a.getSnippet(ctx, vs),
								Remediation: "Initialize maps with make(): m := make(map[K]V) or m := map[K]V{}",
							})
						}
					}
				}
			}
			return true
		})
	}
}

// =============================================================================
// 14. Insecure TLS
// =============================================================================

func (a *Analyzer) checkInsecureTLS(ctx *FileContext) {
	if !ctx.HasImport("crypto/tls") && !ctx.HasImport("net/http") {
		return
	}

	ast.Inspect(ctx.File, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}

		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			return true
		}

		if ident.Name == "InsecureSkipVerify" {
			if lit, ok := kv.Value.(*ast.Ident); ok && lit.Name == "true" {
				a.addVuln(models.Vulnerability{
					Title:       "TLS Certificate Verification Disabled",
					Description: "InsecureSkipVerify: true disables TLS certificate validation, enabling man-in-the-middle attacks",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    "Insecure TLS",
					CWE:         "CWE-295",
					OWASP:       "A07:2021",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(kv),
					EndLine:     a.getEndLine(kv),
					Snippet:     a.getSnippet(ctx, kv),
					Remediation: "Remove InsecureSkipVerify or set to false. Configure proper CA certificates.",
				})
			}
		}

		if ident.Name == "MinVersion" {
			valStr := exprToString(kv.Value)
			if strings.Contains(valStr, "VersionSSL30") || strings.Contains(valStr, "VersionTLS10") ||
				strings.Contains(valStr, "VersionTLS11") {
				a.addVuln(models.Vulnerability{
					Title:       "Weak TLS Version",
					Description: "TLS MinVersion set to deprecated version: " + valStr,
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    "Insecure TLS",
					CWE:         "CWE-326",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(kv),
					EndLine:     a.getEndLine(kv),
					Snippet:     a.getSnippet(ctx, kv),
					Remediation: "Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13.",
				})
			}
		}

		return true
	})
}

// =============================================================================
// 15. CORS Misconfiguration
// =============================================================================

func (a *Analyzer) checkCORSMisconfig(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			if (strings.HasSuffix(funcName, ".Set") || strings.HasSuffix(funcName, ".Add")) &&
				len(call.Args) >= 2 {
				arg0 := exprToString(call.Args[0])
				arg1 := exprToString(call.Args[1])
				if strings.Contains(strings.ToLower(arg0), "access-control-allow-origin") &&
					strings.Contains(arg1, "*") {
					a.addVuln(models.Vulnerability{
						Title:       "CORS Wildcard Origin",
						Description: "Access-Control-Allow-Origin set to '*' allows any website to make cross-origin requests",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceHigh,
						Category:    "CORS Misconfiguration",
						CWE:         "CWE-942",
						OWASP:       "A05:2021",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(call),
						EndLine:     a.getEndLine(call),
						Snippet:     a.getSnippet(ctx, call),
						Remediation: "Restrict CORS to specific trusted origins.",
					})
				}
			}

			return true
		})
	}

	// Check CORS middleware config (AllowAllOrigins)
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if ident, ok := kv.Key.(*ast.Ident); ok {
			if ident.Name == "AllowAllOrigins" {
				valStr := exprToString(kv.Value)
				if valStr == "true" {
					a.addVuln(models.Vulnerability{
						Title:       "CORS Allow All Origins",
						Description: "CORS middleware configured to allow all origins",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceHigh,
						Category:    "CORS Misconfiguration",
						CWE:         "CWE-942",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(kv),
						EndLine:     a.getEndLine(kv),
						Snippet:     a.getSnippet(ctx, kv),
						Remediation: "Specify exact allowed origins.",
					})
				}
			}
		}
		return true
	})
}

// =============================================================================
// 16. Missing Authentication
// =============================================================================

func (a *Analyzer) checkMissingAuth(ctx *FileContext) {
	if !ctx.HasImport("net/http") {
		return
	}

	for _, fn := range a.functions[ctx.Path] {
		if fn.Type == nil || fn.Type.Params == nil || fn.Name == nil {
			continue
		}

		isHTTPHandler := false
		for _, param := range fn.Type.Params.List {
			paramType := exprToString(param.Type)
			if strings.Contains(paramType, "http.ResponseWriter") ||
				strings.Contains(paramType, "http.Request") {
				isHTTPHandler = true
				break
			}
		}
		if !isHTTPHandler {
			continue
		}

		funcName := strings.ToLower(fn.Name.Name)
		sensitiveNames := []string{"admin", "delete", "update", "create", "modify", "upload", "config", "setting"}

		isSensitive := false
		for _, sn := range sensitiveNames {
			if strings.Contains(funcName, sn) {
				isSensitive = true
				break
			}
		}
		if !isSensitive {
			continue
		}

		hasAuthCheck := false
		walkFunc(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				name := strings.ToLower(getFuncName(call))
				if strings.Contains(name, "auth") || strings.Contains(name, "verify") ||
					strings.Contains(name, "check") || strings.Contains(name, "validate") {
					hasAuthCheck = true
					return false
				}
			}
			if ifStmt, ok := n.(*ast.IfStmt); ok {
				condStr := strings.ToLower(exprToString(ifStmt.Cond))
				if strings.Contains(condStr, "auth") || strings.Contains(condStr, "token") ||
					strings.Contains(condStr, "session") {
					hasAuthCheck = true
					return false
				}
			}
			return true
		})

		if !hasAuthCheck {
			a.addVuln(models.Vulnerability{
				Title:       "Potentially Missing Authentication",
				Description: "HTTP handler '" + fn.Name.Name + "' handles sensitive operations without visible authentication checks",
				Severity:    models.SeverityHigh,
				Confidence:  models.ConfidenceLow,
				Category:    "Missing Authentication",
				CWE:         "CWE-306",
				OWASP:       "A07:2021",
				FilePath:    ctx.Path,
				StartLine:   a.getLine(fn),
				EndLine:     a.getLine(fn),
				Snippet:     a.getSnippet(ctx, fn),
				Remediation: "Add authentication middleware or explicit auth checks for sensitive handlers.",
			})
		}
	}
}

// =============================================================================
// 17. Information Disclosure
// =============================================================================

func (a *Analyzer) checkInfoDisclosure(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)

			if funcName == "debug.Stack" || funcName == "runtime.Stack" {
				a.addVuln(models.Vulnerability{
					Title:       "Stack Trace Exposure",
					Description: "Stack trace may be exposed to users through error responses",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceMedium,
					Category:    "Information Disclosure",
					CWE:         "CWE-209",
					OWASP:       "A04:2021",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(call),
					EndLine:     a.getEndLine(call),
					Snippet:     a.getSnippet(ctx, call),
					Remediation: "Do not include stack traces in production error responses. Log them server-side only.",
				})
			}

			if funcName == "http.Error" && len(call.Args) >= 2 {
				errArg := call.Args[1]
				if callExpr, ok := errArg.(*ast.CallExpr); ok {
					if strings.HasSuffix(getFuncName(callExpr), ".Error") {
						a.addVuln(models.Vulnerability{
							Title:       "Detailed Error Message in HTTP Response",
							Description: "Internal error details sent to client via http.Error()",
							Severity:    models.SeverityMedium,
							Confidence:  models.ConfidenceMedium,
							Category:    "Information Disclosure",
							CWE:         "CWE-209",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Return generic error messages to clients. Log detailed errors server-side.",
						})
					}
				}
			}

			return true
		})
	}

	// pprof import
	if ctx.HasImport("net/http/pprof") {
		for _, imp := range ctx.File.Imports {
			importPath := strings.Trim(imp.Path.Value, "\"")
			if importPath == "net/http/pprof" {
				a.addVuln(models.Vulnerability{
					Title:       "Debug Profiling Endpoint Enabled",
					Description: "net/http/pprof imported - exposes /debug/pprof/ endpoints with sensitive runtime data",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    "Information Disclosure",
					CWE:         "CWE-215",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(imp),
					EndLine:     a.getEndLine(imp),
					Snippet:     a.getSnippet(ctx, imp),
					Remediation: "Remove pprof import in production builds.",
				})
			}
		}
	}
}

// =============================================================================
// 18. Template Injection
// =============================================================================

func (a *Analyzer) checkTemplateInjection(ctx *FileContext) {
	if !ctx.HasImport("text/template") && !ctx.HasImport("html/template") {
		return
	}

	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			if strings.HasSuffix(funcName, ".Parse") || strings.HasSuffix(funcName, ".ParseGlob") {
				if len(call.Args) > 0 && tracker.IsExprTainted(call.Args[0]) {
					a.addVuln(models.Vulnerability{
						Title:       "Template Injection",
						Description: "Template parsed from user-controlled input, allowing arbitrary template execution",
						Severity:    models.SeverityCritical,
						Confidence:  models.ConfidenceHigh,
						Category:    "Template Injection",
						CWE:         "CWE-94",
						OWASP:       "A03:2021",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(call),
						EndLine:     a.getEndLine(call),
						Snippet:     a.getSnippet(ctx, call),
						Remediation: "Never parse user input as a template. Use pre-defined templates with template data only.",
					})
				}
			}

			return true
		})
	}
}

// =============================================================================
// 19. Gin-specific
// =============================================================================

func (a *Analyzer) checkGinSpecific(ctx *FileContext) {
	if !ctx.HasImport("github.com/gin-gonic/gin") {
		return
	}

	ast.Inspect(ctx.File, func(n ast.Node) bool {
		// Check for gin.SetMode(gin.DebugMode) or missing release mode
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		funcName := getFuncName(call)

		// Trusted proxy
		if funcName == "gin.SetTrustedProxies" || strings.HasSuffix(funcName, ".SetTrustedProxies") {
			if len(call.Args) > 0 {
				if ident, ok := call.Args[0].(*ast.Ident); ok && ident.Name == "nil" {
					a.addVuln(models.Vulnerability{
						Title:       "Gin - All Proxies Trusted",
						Description: "SetTrustedProxies(nil) trusts all proxies, which can lead to IP spoofing",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceHigh,
						Category:    "Framework Misconfiguration",
						CWE:         "CWE-346",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(call),
						EndLine:     a.getEndLine(call),
						Snippet:     a.getSnippet(ctx, call),
						Remediation: "Set specific trusted proxy IP addresses.",
					})
				}
			}
		}

		// Debug mode
		if funcName == "gin.SetMode" && len(call.Args) > 0 {
			argStr := exprToString(call.Args[0])
			if strings.Contains(argStr, "DebugMode") || strings.Contains(argStr, "debug") {
				a.addVuln(models.Vulnerability{
					Title:       "Gin - Debug Mode Enabled",
					Description: "Gin running in debug mode exposes detailed error information",
					Severity:    models.SeverityLow,
					Confidence:  models.ConfidenceHigh,
					Category:    "Framework Misconfiguration",
					CWE:         "CWE-215",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(call),
					EndLine:     a.getEndLine(call),
					Snippet:     a.getSnippet(ctx, call),
					Remediation: "Use gin.SetMode(gin.ReleaseMode) in production.",
				})
			}
		}

		return true
	})

	// Check for BindJSON without validation
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			funcName := getFuncName(call)
			if strings.HasSuffix(funcName, ".BindJSON") {
				// BindJSON auto-returns 400 but ShouldBindJSON is preferred
				a.addVuln(models.Vulnerability{
					Title:       "Gin - BindJSON Auto-Aborts on Error",
					Description: "BindJSON automatically returns 400 and aborts. Use ShouldBindJSON for custom error handling.",
					Severity:    models.SeverityLow,
					Confidence:  models.ConfidenceLow,
					Category:    "Framework Misconfiguration",
					CWE:         "CWE-754",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(call),
					EndLine:     a.getEndLine(call),
					Snippet:     a.getSnippet(ctx, call),
					Remediation: "Use ShouldBindJSON for better error handling control.",
				})
			}
			return true
		})
	}
}

// =============================================================================
// 20. Echo-specific
// =============================================================================

func (a *Analyzer) checkEchoSpecific(ctx *FileContext) {
	if !ctx.HasImport("github.com/labstack/echo") && !ctx.HasImport("github.com/labstack/echo/v4") {
		return
	}

	// Check for missing CSRF middleware
	hasCSRF := false
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		funcName := getFuncName(call)
		if strings.Contains(funcName, "middleware.CSRF") || strings.Contains(funcName, "csrf.") {
			hasCSRF = true
			return false
		}
		return true
	})

	if !hasCSRF {
		// Only flag if this looks like a main/router setup file
		for _, fn := range a.functions[ctx.Path] {
			if fn.Name != nil && (fn.Name.Name == "main" || strings.Contains(strings.ToLower(fn.Name.Name), "route") ||
				strings.Contains(strings.ToLower(fn.Name.Name), "setup")) {
				a.addVuln(models.Vulnerability{
					Title:       "Echo - Missing CSRF Protection",
					Description: "Echo application does not appear to use CSRF middleware",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceLow,
					Category:    "Framework Misconfiguration",
					CWE:         "CWE-352",
					OWASP:       "A05:2021",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(fn),
					EndLine:     a.getLine(fn),
					Snippet:     a.getSnippet(ctx, fn),
					Remediation: "Add CSRF middleware: e.Use(middleware.CSRF())",
				})
				break
			}
		}
	}
}

// =============================================================================
// 21. Fiber-specific
// =============================================================================

func (a *Analyzer) checkFiberSpecific(ctx *FileContext) {
	if !ctx.HasImport("github.com/gofiber/fiber") && !ctx.HasImport("github.com/gofiber/fiber/v2") {
		return
	}

	// Check for Prefork (unsafe with shared listeners)
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if ident, ok := kv.Key.(*ast.Ident); ok {
			if ident.Name == "Prefork" {
				if lit, ok := kv.Value.(*ast.Ident); ok && lit.Name == "true" {
					a.addVuln(models.Vulnerability{
						Title:       "Fiber - Prefork Mode Enabled",
						Description: "Prefork mode spawns multiple processes sharing the same listener, which can cause issues with middleware state",
						Severity:    models.SeverityLow,
						Confidence:  models.ConfidenceMedium,
						Category:    "Framework Misconfiguration",
						CWE:         "CWE-362",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(kv),
						EndLine:     a.getEndLine(kv),
						Snippet:     a.getSnippet(ctx, kv),
						Remediation: "Be cautious with Prefork mode. Ensure middleware and state are process-safe.",
					})
				}
			}
		}
		return true
	})
}

// =============================================================================
// 22. gRPC-specific
// =============================================================================

func (a *Analyzer) checkGRPCSpecific(ctx *FileContext) {
	if !ctx.HasImport("google.golang.org/grpc") {
		return
	}

	// Check for insecure gRPC (no TLS)
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		funcName := getFuncName(call)

		if funcName == "grpc.Dial" || funcName == "grpc.DialContext" {
			hasInsecure := false
			for _, arg := range call.Args {
				argStr := exprToString(arg)
				if strings.Contains(argStr, "WithInsecure") || strings.Contains(argStr, "insecure") {
					hasInsecure = true
				}
			}
			if hasInsecure {
				a.addVuln(models.Vulnerability{
					Title:       "gRPC - Insecure Connection",
					Description: "gRPC connection without TLS (WithInsecure). Traffic is unencrypted.",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    "Insecure Communication",
					CWE:         "CWE-319",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(call),
					EndLine:     a.getEndLine(call),
					Snippet:     a.getSnippet(ctx, call),
					Remediation: "Use TLS credentials: grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))",
				})
			}
		}

		// NewServer without interceptors
		if funcName == "grpc.NewServer" {
			hasInterceptor := false
			for _, arg := range call.Args {
				argStr := exprToString(arg)
				if strings.Contains(argStr, "Interceptor") || strings.Contains(argStr, "interceptor") {
					hasInterceptor = true
				}
			}
			if !hasInterceptor {
				a.addVuln(models.Vulnerability{
					Title:       "gRPC - Server Without Interceptors",
					Description: "gRPC server created without unary/stream interceptors for auth, logging, or rate limiting",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceLow,
					Category:    "Missing Authentication",
					CWE:         "CWE-306",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(call),
					EndLine:     a.getEndLine(call),
					Snippet:     a.getSnippet(ctx, call),
					Remediation: "Add interceptors for authentication and logging.",
				})
			}
		}

		return true
	})
}

// =============================================================================
// 23. Unsafe Package
// =============================================================================

func (a *Analyzer) checkUnsafePackage(ctx *FileContext) {
	if !ctx.HasImport("unsafe") {
		return
	}

	for _, imp := range ctx.File.Imports {
		importPath := strings.Trim(imp.Path.Value, "\"")
		if importPath == "unsafe" {
			a.addVuln(models.Vulnerability{
				Title:       "Unsafe Package Usage",
				Description: "Package 'unsafe' imported. This bypasses Go's type safety and memory safety guarantees.",
				Severity:    models.SeverityHigh,
				Confidence:  models.ConfidenceHigh,
				Category:    "Unsafe Code",
				CWE:         "CWE-676",
				FilePath:    ctx.Path,
				StartLine:   a.getLine(imp),
				EndLine:     a.getEndLine(imp),
				Snippet:     a.getSnippet(ctx, imp),
				Remediation: "Avoid unsafe package unless absolutely necessary. Ensure all unsafe operations are thoroughly reviewed.",
			})
		}
	}

	// Check for unsafe.Pointer usage
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok {
			if ident.Name == "unsafe" && sel.Sel.Name == "Pointer" {
				a.addVuln(models.Vulnerability{
					Title:       "Unsafe Pointer Cast",
					Description: "unsafe.Pointer used for type conversion, bypassing type safety",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Category:    "Unsafe Code",
					CWE:         "CWE-843",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(sel),
					EndLine:     a.getEndLine(sel),
					Snippet:     a.getSnippet(ctx, sel),
					Remediation: "Use safe type conversions or the reflect package instead.",
				})
			}
		}
		return true
	})
}

// =============================================================================
// 24. Goroutine Leaks
// =============================================================================

func (a *Analyzer) checkGoroutineLeaks(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		if fn.Body == nil {
			continue
		}

		// Check for goroutines with unbuffered channels and no context
		walkFunc(fn, func(n ast.Node) bool {
			goStmt, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}

			// Check if goroutine uses context for cancellation
			hasContext := false
			hasSelect := false
			ast.Inspect(goStmt.Call, func(inner ast.Node) bool {
				if ident, ok := inner.(*ast.Ident); ok {
					if ident.Name == "ctx" || strings.Contains(ident.Name, "context") ||
						strings.Contains(ident.Name, "done") || strings.Contains(ident.Name, "cancel") {
						hasContext = true
					}
				}
				if _, ok := inner.(*ast.SelectStmt); ok {
					hasSelect = true
				}
				return true
			})

			// Goroutine with for{} loop but no context/select
			hasForLoop := false
			ast.Inspect(goStmt.Call, func(inner ast.Node) bool {
				if _, ok := inner.(*ast.ForStmt); ok {
					hasForLoop = true
				}
				if _, ok := inner.(*ast.RangeStmt); ok {
					hasForLoop = true
				}
				return true
			})

			if hasForLoop && !hasContext && !hasSelect {
				a.addVuln(models.Vulnerability{
					Title:       "Potential Goroutine Leak",
					Description: "Goroutine contains a loop without context cancellation or select statement",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceMedium,
					Category:    "Goroutine Leak",
					CWE:         "CWE-400",
					FilePath:    ctx.Path,
					StartLine:   a.getLine(goStmt),
					EndLine:     a.getEndLine(goStmt),
					Snippet:     a.getSnippet(ctx, goStmt),
					Remediation: "Use context.Context with cancellation to allow goroutines to be stopped. Add a select case for ctx.Done().",
				})
			}

			return true
		})

		// Check for channel creation without consumers
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "make" {
				if len(call.Args) > 0 {
					if _, ok := call.Args[0].(*ast.ChanType); ok {
						if len(call.Args) == 1 {
							// Unbuffered channel - more prone to goroutine leaks
							a.addVuln(models.Vulnerability{
								Title:       "Unbuffered Channel May Cause Goroutine Leak",
								Description: "Unbuffered channel created. Sends will block until a receiver is ready, potentially causing goroutine leaks.",
								Severity:    models.SeverityLow,
								Confidence:  models.ConfidenceLow,
								Category:    "Goroutine Leak",
								CWE:         "CWE-400",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(call),
								EndLine:     a.getEndLine(call),
								Snippet:     a.getSnippet(ctx, call),
								Remediation: "Consider using a buffered channel or ensure all senders have corresponding receivers.",
							})
						}
					}
				}
			}
			return true
		})
	}
}

// =============================================================================
// 25. JWT Issues
// =============================================================================

func (a *Analyzer) checkJWTIssues(ctx *FileContext) {
	if !ctx.HasImport("github.com/dgrijalva/jwt-go") &&
		!ctx.HasImport("github.com/golang-jwt/jwt") &&
		!ctx.HasImport("github.com/golang-jwt/jwt/v4") &&
		!ctx.HasImport("github.com/golang-jwt/jwt/v5") {
		return
	}

	ast.Inspect(ctx.File, func(n ast.Node) bool {
		// Check for "none" algorithm
		kv, ok := n.(*ast.KeyValueExpr)
		if ok {
			if ident, ok := kv.Key.(*ast.Ident); ok {
				if ident.Name == "SigningMethod" || ident.Name == "Algorithm" {
					valStr := exprToString(kv.Value)
					if strings.Contains(strings.ToLower(valStr), "none") {
						a.addVuln(models.Vulnerability{
							Title:       "JWT None Algorithm",
							Description: "JWT configured with 'none' algorithm, allowing token forgery",
							Severity:    models.SeverityCritical,
							Confidence:  models.ConfidenceHigh,
							Category:    "JWT Security",
							CWE:         "CWE-327",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(kv),
							EndLine:     a.getEndLine(kv),
							Snippet:     a.getSnippet(ctx, kv),
							Remediation: "Always use a strong signing algorithm (RS256, ES256, HS256 with strong secret).",
						})
					}
				}
			}
		}

		// Check for weak JWT secret
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		funcName := getFuncName(call)
		if strings.Contains(funcName, "SignedString") || strings.Contains(funcName, "Parse") {
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					val := strings.Trim(lit.Value, "\"")
					if len(val) < 32 {
						a.addVuln(models.Vulnerability{
							Title:       "Weak JWT Secret",
							Description: "JWT signed with a short/weak secret key (" + fmt.Sprintf("%d", len(val)) + " chars). Minimum 32 characters recommended.",
							Severity:    models.SeverityHigh,
							Confidence:  models.ConfidenceMedium,
							Category:    "JWT Security",
							CWE:         "CWE-326",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Use a cryptographically random secret of at least 256 bits (32 bytes). Store in environment variable.",
						})
					}
				}
			}
		}

		return true
	})
}

// =============================================================================
// 26. Open Redirect
// =============================================================================

func (a *Analyzer) checkOpenRedirect(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			if funcName == "http.Redirect" && len(call.Args) >= 3 {
				urlArg := call.Args[2]
				if tracker.IsExprTainted(urlArg) {
					a.addVuln(models.Vulnerability{
						Title:       "Open Redirect",
						Description: "HTTP redirect URL is user-controlled, allowing redirection to malicious sites",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceHigh,
						Category:    "Open Redirect",
						CWE:         "CWE-601",
						OWASP:       "A01:2021",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(call),
						EndLine:     a.getEndLine(call),
						Snippet:     a.getSnippet(ctx, call),
						Remediation: "Validate redirect URLs against an allowlist of safe domains. Only allow relative URLs or specific trusted domains.",
					})
				}
			}

			// Gin/Echo redirect
			if strings.HasSuffix(funcName, ".Redirect") && len(call.Args) >= 2 {
				urlArg := call.Args[1]
				if tracker.IsExprTainted(urlArg) {
					a.addVuln(models.Vulnerability{
						Title:       "Open Redirect",
						Description: "Redirect URL from user input",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceHigh,
						Category:    "Open Redirect",
						CWE:         "CWE-601",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(call),
						EndLine:     a.getEndLine(call),
						Snippet:     a.getSnippet(ctx, call),
						Remediation: "Validate redirect URLs against an allowlist.",
					})
				}
			}

			return true
		})
	}
}

// =============================================================================
// 27. File Upload
// =============================================================================

func (a *Analyzer) checkFileUpload(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)

			// r.FormFile, c.FormFile
			if strings.HasSuffix(funcName, ".FormFile") || strings.HasSuffix(funcName, ".MultipartForm") ||
				strings.HasSuffix(funcName, ".SaveUploadedFile") {

				// Check if there is size/type validation in the function
				hasValidation := false
				walkFunc(fn, func(inner ast.Node) bool {
					if innerCall, ok := inner.(*ast.CallExpr); ok {
						name := getFuncName(innerCall)
						if strings.Contains(name, "ContentType") || strings.Contains(name, "DetectContentType") ||
							strings.Contains(name, "MaxBytesReader") || strings.Contains(name, "ParseMultipartForm") {
							hasValidation = true
							return false
						}
					}
					return true
				})

				if !hasValidation {
					a.addVuln(models.Vulnerability{
						Title:       "File Upload Without Validation",
						Description: "File upload handler without visible content type or size validation",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceMedium,
						Category:    "File Upload",
						CWE:         "CWE-434",
						OWASP:       "A04:2021",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(call),
						EndLine:     a.getEndLine(call),
						Snippet:     a.getSnippet(ctx, call),
						Remediation: "Validate file type (content type, magic bytes), size (http.MaxBytesReader), and sanitize filename.",
					})
				}
			}

			return true
		})
	}
}

// =============================================================================
// 28. Logging Sensitive Data
// =============================================================================

func (a *Analyzer) checkLoggingSensitiveData(ctx *FileContext) {
	sensitiveVarNames := []string{"password", "passwd", "pwd", "secret", "token", "apikey",
		"api_key", "credit_card", "creditcard", "ssn", "private_key", "privatekey",
		"access_token", "accesstoken", "auth_token", "authtoken"}

	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			isLogCall := strings.Contains(funcName, "log.") || strings.Contains(funcName, "Log") ||
				strings.Contains(funcName, "Print") || strings.Contains(funcName, "Debug") ||
				strings.Contains(funcName, "Info") || strings.Contains(funcName, "Warn") ||
				strings.Contains(funcName, "Error") || strings.Contains(funcName, "Fatal")

			if !isLogCall {
				return true
			}

			for _, arg := range call.Args {
				argStr := strings.ToLower(exprToString(arg))
				for _, sensitive := range sensitiveVarNames {
					if strings.Contains(argStr, sensitive) {
						a.addVuln(models.Vulnerability{
							Title:       "Sensitive Data in Log",
							Description: "Potentially sensitive variable '" + sensitive + "' logged in " + funcName,
							Severity:    models.SeverityMedium,
							Confidence:  models.ConfidenceMedium,
							Category:    "Logging Sensitive Data",
							CWE:         "CWE-532",
							OWASP:       "A09:2021",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Never log passwords, tokens, or other sensitive data. Mask or redact sensitive fields before logging.",
						})
						break
					}
				}
			}

			return true
		})
	}
}

// =============================================================================
// 29. Mass Assignment
// =============================================================================

func (a *Analyzer) checkMassAssignment(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		tracker := NewTaintTracker()
		tracker.TrackFunction(fn, a.fset)

		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)

			// json.Unmarshal / json.Decode into a struct from user input
			if funcName == "json.Unmarshal" || strings.HasSuffix(funcName, ".Decode") {
				for _, arg := range call.Args {
					if tracker.IsExprTainted(arg) {
						a.addVuln(models.Vulnerability{
							Title:       "Potential Mass Assignment",
							Description: "JSON unmarshaling from user input into struct. All exported fields will be populated.",
							Severity:    models.SeverityMedium,
							Confidence:  models.ConfidenceLow,
							Category:    "Mass Assignment",
							CWE:         "CWE-915",
							OWASP:       "A08:2021",
							FilePath:    ctx.Path,
							StartLine:   a.getLine(call),
							EndLine:     a.getEndLine(call),
							Snippet:     a.getSnippet(ctx, call),
							Remediation: "Use separate DTOs for input. Only copy whitelisted fields to domain objects. Use json:\"-\" to exclude sensitive fields.",
						})
						break
					}
				}
			}

			return true
		})
	}
}

// =============================================================================
// 30. Timing Attacks
// =============================================================================

func (a *Analyzer) checkTimingAttacks(ctx *FileContext) {
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			// Check for == comparison of secrets/tokens/passwords
			binaryExpr, ok := n.(*ast.BinaryExpr)
			if !ok {
				return true
			}

			if binaryExpr.Op != token.EQL && binaryExpr.Op != token.NEQ {
				return true
			}

			lhs := strings.ToLower(exprToString(binaryExpr.X))
			rhs := strings.ToLower(exprToString(binaryExpr.Y))

			sensitiveNames := []string{"password", "token", "secret", "hash", "key", "signature",
				"hmac", "digest", "apikey", "api_key", "auth"}

			for _, sensitive := range sensitiveNames {
				if strings.Contains(lhs, sensitive) || strings.Contains(rhs, sensitive) {
					a.addVuln(models.Vulnerability{
						Title:       "Timing Attack - Non-Constant-Time Comparison",
						Description: "Secret/token compared using == which is vulnerable to timing attacks",
						Severity:    models.SeverityMedium,
						Confidence:  models.ConfidenceMedium,
						Category:    "Timing Attack",
						CWE:         "CWE-208",
						FilePath:    ctx.Path,
						StartLine:   a.getLine(binaryExpr),
						EndLine:     a.getEndLine(binaryExpr),
						Snippet:     a.getSnippet(ctx, binaryExpr),
						Remediation: "Use subtle.ConstantTimeCompare() from crypto/subtle for comparing secrets, tokens, and passwords.",
					})
					break
				}
			}

			return true
		})
	}

	// Check for bytes.Equal on secrets
	for _, fn := range a.functions[ctx.Path] {
		walkFunc(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			funcName := getFuncName(call)
			if funcName == "bytes.Equal" || funcName == "strings.Compare" || funcName == "bytes.Compare" {
				for _, arg := range call.Args {
					argStr := strings.ToLower(exprToString(arg))
					sensitiveNames := []string{"password", "token", "secret", "hash", "key", "hmac"}
					for _, s := range sensitiveNames {
						if strings.Contains(argStr, s) {
							a.addVuln(models.Vulnerability{
								Title:       "Timing Attack - Non-Constant-Time Comparison",
								Description: funcName + " used for comparing potentially sensitive data",
								Severity:    models.SeverityMedium,
								Confidence:  models.ConfidenceMedium,
								Category:    "Timing Attack",
								CWE:         "CWE-208",
								FilePath:    ctx.Path,
								StartLine:   a.getLine(call),
								EndLine:     a.getEndLine(call),
								Snippet:     a.getSnippet(ctx, call),
								Remediation: "Use subtle.ConstantTimeCompare() from crypto/subtle.",
							})
							return false
						}
					}
				}
			}

			return true
		})
	}
}
