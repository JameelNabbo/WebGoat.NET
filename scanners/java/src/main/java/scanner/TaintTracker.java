package scanner;

import com.github.javaparser.ast.*;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;

import java.util.*;

/**
 * Tracks tainted data flow through Java source code.
 * Identifies sources (user input), sinks (dangerous operations),
 * and traces how tainted data propagates through variables and method calls.
 */
public class TaintTracker {

    // Taint sources - methods that return user-controlled input
    private static final Set<String> TAINT_SOURCES = new HashSet<>(Arrays.asList(
        // Servlet sources
        "getParameter", "getParameterValues", "getParameterMap", "getParameterNames",
        "getHeader", "getHeaders", "getHeaderNames",
        "getCookies", "getQueryString", "getRequestURI", "getRequestURL",
        "getPathInfo", "getPathTranslated", "getInputStream", "getReader",
        "getPart", "getParts", "getRemoteAddr", "getRemoteHost",
        // Spring sources
        "getBody",
        // General I/O sources
        "readLine", "read", "readAllBytes", "readAllLines",
        "nextLine", "next", "nextInt", "nextDouble",
        // Environment
        "getenv", "getProperty",
        // Database results
        "getString", "getObject", "getInt", "getLong",
        // Request body
        "getJSON", "getText"
    ));

    // Sanitizers - methods that clean tainted data
    private static final Set<String> SANITIZERS = new HashSet<>(Arrays.asList(
        "escapeHtml", "escapeXml", "escapeSql", "escapeJavaScript",
        "htmlEscape", "sanitize", "encode", "encodeForHTML",
        "encodeForJavaScript", "encodeForURL", "encodeForSQL",
        "stripTags", "clean", "purify", "validate",
        "parseInt", "parseLong", "parseDouble", "parseFloat",
        "valueOf", "trim", "strip",
        "prepareStatement", "setString", "setInt", "setLong",
        "parameterize", "bind"
    ));

    // Map of variable name -> taint info
    private Map<String, TaintInfo> taintedVariables = new HashMap<>();

    // Track parameter annotations that indicate taint sources
    private static final Set<String> TAINT_ANNOTATIONS = new HashSet<>(Arrays.asList(
        "RequestParam", "PathVariable", "RequestBody", "RequestHeader",
        "CookieValue", "MatrixVariable", "ModelAttribute",
        "RequestPart"
    ));

    public static class TaintInfo {
        public String variableName;
        public String sourceMethod;
        public int sourceLine;
        public String sourceFile;
        public boolean isTainted;
        public boolean isSanitized;
        public List<VulnerabilityReport.DataFlowStep> flowPath;

        public TaintInfo(String variableName, String sourceMethod, int sourceLine, String sourceFile) {
            this.variableName = variableName;
            this.sourceMethod = sourceMethod;
            this.sourceLine = sourceLine;
            this.sourceFile = sourceFile;
            this.isTainted = true;
            this.isSanitized = false;
            this.flowPath = new ArrayList<>();
            this.flowPath.add(new VulnerabilityReport.DataFlowStep(
                sourceFile, sourceLine, sourceMethod, "Source: user input via " + sourceMethod
            ));
        }

        public TaintInfo propagate(String newVar, int line, String code, String file) {
            TaintInfo newInfo = new TaintInfo(newVar, this.sourceMethod, this.sourceLine, this.sourceFile);
            newInfo.flowPath = new ArrayList<>(this.flowPath);
            newInfo.flowPath.add(new VulnerabilityReport.DataFlowStep(
                file, line, code, "Propagation: taint flows to " + newVar
            ));
            return newInfo;
        }
    }

    /**
     * Analyze a method to track tainted data flows.
     */
    public void analyzeMethod(MethodDeclaration method, String filePath) {
        // Check method parameters for taint sources
        for (Parameter param : method.getParameters()) {
            boolean isTaintedParam = false;

            // Check for Spring annotations
            for (AnnotationExpr ann : param.getAnnotations()) {
                if (TAINT_ANNOTATIONS.contains(ann.getNameAsString())) {
                    isTaintedParam = true;
                    break;
                }
            }

            // Check parameter type for servlet types
            String paramType = param.getTypeAsString();
            if (paramType.contains("HttpServletRequest") || paramType.contains("ServletRequest") ||
                paramType.contains("MultipartFile") || paramType.contains("WebRequest")) {
                isTaintedParam = true;
            }

            if (isTaintedParam) {
                int line = param.getBegin().map(p -> p.line).orElse(0);
                taintedVariables.put(param.getNameAsString(),
                    new TaintInfo(param.getNameAsString(), "parameter:" + param.getNameAsString(),
                        line, filePath));
            }
        }

        // Walk method body for taint propagation
        method.getBody().ifPresent(body -> {
            analyzeBlock(body, filePath);
        });
    }

    private void analyzeBlock(BlockStmt block, String filePath) {
        for (Statement stmt : block.getStatements()) {
            analyzeStatement(stmt, filePath);
        }
    }

    private void analyzeStatement(Statement stmt, String filePath) {
        if (stmt instanceof ExpressionStmt) {
            Expression expr = ((ExpressionStmt) stmt).getExpression();
            analyzeExpression(expr, filePath);
        } else if (stmt instanceof ReturnStmt) {
            ((ReturnStmt) stmt).getExpression().ifPresent(e -> analyzeExpression(e, filePath));
        } else if (stmt instanceof IfStmt) {
            IfStmt ifStmt = (IfStmt) stmt;
            if (ifStmt.getThenStmt() instanceof BlockStmt) {
                analyzeBlock((BlockStmt) ifStmt.getThenStmt(), filePath);
            }
            ifStmt.getElseStmt().ifPresent(s -> {
                if (s instanceof BlockStmt) analyzeBlock((BlockStmt) s, filePath);
            });
        } else if (stmt instanceof ForStmt) {
            Statement body = ((ForStmt) stmt).getBody();
            if (body instanceof BlockStmt) analyzeBlock((BlockStmt) body, filePath);
        } else if (stmt instanceof ForEachStmt) {
            Statement body = ((ForEachStmt) stmt).getBody();
            if (body instanceof BlockStmt) analyzeBlock((BlockStmt) body, filePath);
        } else if (stmt instanceof WhileStmt) {
            Statement body = ((WhileStmt) stmt).getBody();
            if (body instanceof BlockStmt) analyzeBlock((BlockStmt) body, filePath);
        } else if (stmt instanceof TryStmt) {
            TryStmt tryStmt = (TryStmt) stmt;
            analyzeBlock(tryStmt.getTryBlock(), filePath);
            for (CatchClause cc : tryStmt.getCatchClauses()) {
                analyzeBlock(cc.getBody(), filePath);
            }
            tryStmt.getFinallyBlock().ifPresent(b -> analyzeBlock(b, filePath));
        }
    }

    private void analyzeExpression(Expression expr, String filePath) {
        int line = expr.getBegin().map(p -> p.line).orElse(0);

        // Variable declaration with taint source
        if (expr instanceof VariableDeclarationExpr) {
            VariableDeclarationExpr vde = (VariableDeclarationExpr) expr;
            for (VariableDeclarator vd : vde.getVariables()) {
                vd.getInitializer().ifPresent(init -> {
                    if (isExpressionTainted(init)) {
                        String varName = vd.getNameAsString();
                        String source = getTaintSource(init);
                        taintedVariables.put(varName,
                            new TaintInfo(varName, source, line, filePath));
                    }
                });
            }
        }
        // Assignment with taint propagation
        else if (expr instanceof AssignExpr) {
            AssignExpr ae = (AssignExpr) expr;
            if (isExpressionTainted(ae.getValue())) {
                String targetName = ae.getTarget().toString();
                String source = getTaintSource(ae.getValue());
                TaintInfo existingTaint = findTaintInExpression(ae.getValue());
                if (existingTaint != null) {
                    taintedVariables.put(targetName,
                        existingTaint.propagate(targetName, line, expr.toString(), filePath));
                } else {
                    taintedVariables.put(targetName,
                        new TaintInfo(targetName, source, line, filePath));
                }
            }
        }
    }

    /**
     * Check if an expression contains tainted data.
     */
    public boolean isExpressionTainted(Expression expr) {
        if (expr == null) return false;

        // Direct taint source call
        if (expr instanceof MethodCallExpr) {
            MethodCallExpr mce = (MethodCallExpr) expr;
            String methodName = mce.getNameAsString();

            // Check if it is a sanitizer
            if (SANITIZERS.contains(methodName)) {
                return false;
            }

            // Check if it is a known taint source
            if (TAINT_SOURCES.contains(methodName)) {
                return true;
            }

            // Check if called on a tainted object
            if (mce.getScope().isPresent()) {
                Expression scope = mce.getScope().get();
                if (isExpressionTainted(scope)) {
                    return true;
                }
            }

            // Check method arguments for taint
            for (Expression arg : mce.getArguments()) {
                if (isExpressionTainted(arg)) {
                    return !SANITIZERS.contains(methodName);
                }
            }
        }

        // Variable reference
        if (expr instanceof NameExpr) {
            String varName = ((NameExpr) expr).getNameAsString();
            TaintInfo info = taintedVariables.get(varName);
            return info != null && info.isTainted && !info.isSanitized;
        }

        // String concatenation
        if (expr instanceof BinaryExpr) {
            BinaryExpr be = (BinaryExpr) expr;
            return isExpressionTainted(be.getLeft()) || isExpressionTainted(be.getRight());
        }

        // String addition assignment
        if (expr instanceof AssignExpr) {
            AssignExpr ae = (AssignExpr) expr;
            return isExpressionTainted(ae.getValue()) || isExpressionTainted(ae.getTarget());
        }

        // Cast expression
        if (expr instanceof CastExpr) {
            return isExpressionTainted(((CastExpr) expr).getExpression());
        }

        // Enclosed expression (parenthesized)
        if (expr instanceof EnclosedExpr) {
            return isExpressionTainted(((EnclosedExpr) expr).getInner());
        }

        // Conditional expression (ternary)
        if (expr instanceof ConditionalExpr) {
            ConditionalExpr ce = (ConditionalExpr) expr;
            return isExpressionTainted(ce.getThenExpr()) || isExpressionTainted(ce.getElseExpr());
        }

        // Field access on tainted object
        if (expr instanceof FieldAccessExpr) {
            return isExpressionTainted(((FieldAccessExpr) expr).getScope());
        }

        return false;
    }

    /**
     * Get the original taint source description.
     */
    public String getTaintSource(Expression expr) {
        if (expr instanceof MethodCallExpr) {
            MethodCallExpr mce = (MethodCallExpr) expr;
            if (TAINT_SOURCES.contains(mce.getNameAsString())) {
                return mce.toString();
            }
            if (mce.getScope().isPresent() && isExpressionTainted(mce.getScope().get())) {
                return getTaintSource(mce.getScope().get());
            }
            for (Expression arg : mce.getArguments()) {
                if (isExpressionTainted(arg)) {
                    return getTaintSource(arg);
                }
            }
        }
        if (expr instanceof NameExpr) {
            String varName = ((NameExpr) expr).getNameAsString();
            TaintInfo info = taintedVariables.get(varName);
            if (info != null) {
                return info.sourceMethod;
            }
        }
        if (expr instanceof BinaryExpr) {
            BinaryExpr be = (BinaryExpr) expr;
            if (isExpressionTainted(be.getLeft())) return getTaintSource(be.getLeft());
            if (isExpressionTainted(be.getRight())) return getTaintSource(be.getRight());
        }
        return expr.toString();
    }

    /**
     * Find taint info for a tainted expression.
     */
    public TaintInfo findTaintInExpression(Expression expr) {
        if (expr instanceof NameExpr) {
            return taintedVariables.get(((NameExpr) expr).getNameAsString());
        }
        if (expr instanceof MethodCallExpr) {
            MethodCallExpr mce = (MethodCallExpr) expr;
            if (mce.getScope().isPresent()) {
                TaintInfo info = findTaintInExpression(mce.getScope().get());
                if (info != null) return info;
            }
            for (Expression arg : mce.getArguments()) {
                TaintInfo info = findTaintInExpression(arg);
                if (info != null) return info;
            }
        }
        if (expr instanceof BinaryExpr) {
            TaintInfo left = findTaintInExpression(((BinaryExpr) expr).getLeft());
            if (left != null) return left;
            return findTaintInExpression(((BinaryExpr) expr).getRight());
        }
        return null;
    }

    /**
     * Check if a variable name refers to tainted data.
     */
    public boolean isVariableTainted(String varName) {
        TaintInfo info = taintedVariables.get(varName);
        return info != null && info.isTainted && !info.isSanitized;
    }

    /**
     * Get taint info for a variable.
     */
    public TaintInfo getTaintInfo(String varName) {
        return taintedVariables.get(varName);
    }

    /**
     * Mark a variable as tainted.
     */
    public void markTainted(String varName, String source, int line, String file) {
        taintedVariables.put(varName, new TaintInfo(varName, source, line, file));
    }

    /**
     * Reset taint state (call between methods/files).
     */
    public void reset() {
        taintedVariables.clear();
    }

    /**
     * Get all currently tainted variables.
     */
    public Map<String, TaintInfo> getTaintedVariables() {
        return Collections.unmodifiableMap(taintedVariables);
    }
}
