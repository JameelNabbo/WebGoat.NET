package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;

import java.util.*;

public class SqlInjectionRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-SQL-001"; }
    @Override public String getCategory() { return "SQL Injection"; }

    private static final Set<String> SQL_EXEC_METHODS = new HashSet<>(Arrays.asList(
        "execute", "executeQuery", "executeUpdate", "executeBatch",
        "addBatch", "prepareStatement", "prepareCall",
        "createQuery", "createNativeQuery", "createSQLQuery",
        "find", "list", "uniqueResult", "getResultList", "getSingleResult"
    ));

    private static final Set<String> SQL_KEYWORDS = new HashSet<>(Arrays.asList(
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
        "ALTER", "EXEC", "EXECUTE", "UNION", "FROM", "WHERE",
        "ORDER BY", "GROUP BY", "HAVING"
    ));

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            TaintTracker localTracker = new TaintTracker();
            localTracker.analyzeMethod(method, filePath);

            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String methodName = mce.getNameAsString();
                if (!SQL_EXEC_METHODS.contains(methodName)) return;

                for (Expression arg : mce.getArguments()) {
                    // Check for string concatenation with potential user input
                    if (arg instanceof BinaryExpr) {
                        BinaryExpr be = (BinaryExpr) arg;
                        if (be.getOperator() == BinaryExpr.Operator.PLUS) {
                            if (containsSqlKeyword(be.toString()) && hasDynamicParts(be, localTracker)) {
                                int line = mce.getBegin().map(p -> p.line).orElse(0);
                                String snippet = getSnippet(sourceCode, line);
                                vulns.add(VulnerabilityReport.builder()
                                    .category("SQL Injection")
                                    .severity("Critical")
                                    .title("SQL Injection via string concatenation in " + methodName + "()")
                                    .description("User input is concatenated into a SQL query string passed to " + methodName + "(). " +
                                        "An attacker can manipulate the query to access unauthorized data, modify records, or execute administrative operations.")
                                    .filePath(filePath)
                                    .lineNumber(line)
                                    .codeSnippet(snippet)
                                    .cweId("CWE-89")
                                    .owaspCategory("A03:2021 - Injection")
                                    .recommendation("Use parameterized queries (PreparedStatement) with placeholders. " +
                                        "Never concatenate user input into SQL strings. Use an ORM like JPA/Hibernate with parameterized queries.")
                                    .confidence(localTracker.isExpressionTainted(arg) ? "High" : "Medium")
                                    .build());
                            }
                        }
                    }

                    // Check for String.format with SQL
                    if (arg instanceof MethodCallExpr) {
                        MethodCallExpr innerCall = (MethodCallExpr) arg;
                        if (innerCall.getNameAsString().equals("format") &&
                            innerCall.getArguments().size() > 1 &&
                            containsSqlKeyword(innerCall.getArgument(0).toString())) {
                            int line = mce.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("SQL Injection")
                                .severity("Critical")
                                .title("SQL Injection via String.format() in " + methodName + "()")
                                .description("String.format() is used to construct a SQL query with dynamic values. " +
                                    "This is equivalent to string concatenation and bypasses parameterized query protection.")
                                .filePath(filePath)
                                .lineNumber(line)
                                .codeSnippet(getSnippet(sourceCode, line))
                                .cweId("CWE-89")
                                .owaspCategory("A03:2021 - Injection")
                                .recommendation("Replace String.format() with PreparedStatement parameterized queries.")
                                .confidence("High")
                                .build());
                        }
                    }

                    // Direct tainted variable in SQL method
                    if (arg instanceof NameExpr && localTracker.isExpressionTainted(arg)) {
                        if (containsSqlContext(method.toString())) {
                            int line = mce.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("SQL Injection")
                                .severity("Critical")
                                .title("Tainted input passed to SQL execution method " + methodName + "()")
                                .description("A variable containing user-controlled input is passed directly to " + methodName + "(). " +
                                    "This allows SQL injection attacks.")
                                .filePath(filePath)
                                .lineNumber(line)
                                .codeSnippet(getSnippet(sourceCode, line))
                                .cweId("CWE-89")
                                .owaspCategory("A03:2021 - Injection")
                                .recommendation("Use parameterized queries with PreparedStatement.")
                                .confidence("High")
                                .dataFlow(localTracker.getTaintInfo(((NameExpr) arg).getNameAsString()) != null ?
                                    localTracker.getTaintInfo(((NameExpr) arg).getNameAsString()).flowPath : null)
                                .build());
                        }
                    }
                }
            });

            // Check JPA @Query annotations for injection
            method.getAnnotations().forEach(ann -> {
                if (ann.getNameAsString().equals("Query")) {
                    String annStr = ann.toString();
                    // Check for native query with concatenation or SpEL
                    if (annStr.contains("nativeQuery") && annStr.contains("true")) {
                        if (annStr.contains("#{") || annStr.contains("${") || annStr.contains(":#{")) {
                            int line = ann.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("SQL Injection")
                                .severity("High")
                                .title("Potential SQL Injection in JPA @Query annotation")
                                .description("A native JPA @Query uses Spring Expression Language (SpEL) to inject values. " +
                                    "If not properly validated, this can lead to SQL injection.")
                                .filePath(filePath)
                                .lineNumber(line)
                                .codeSnippet(getSnippet(sourceCode, line))
                                .cweId("CWE-89")
                                .owaspCategory("A03:2021 - Injection")
                                .recommendation("Use named parameters (:paramName) instead of SpEL expressions in @Query.")
                                .confidence("Medium")
                                .build());
                        }
                    }
                }
            });
        });

        return vulns;
    }

    private boolean containsSqlKeyword(String s) {
        String upper = s.toUpperCase();
        for (String kw : SQL_KEYWORDS) {
            if (upper.contains(kw)) return true;
        }
        return false;
    }

    private boolean containsSqlContext(String s) {
        return containsSqlKeyword(s) ||
            s.contains("Statement") || s.contains("Query") ||
            s.contains("createQuery") || s.contains("prepareStatement");
    }

    private boolean hasDynamicParts(BinaryExpr be, TaintTracker tracker) {
        // Check if any part of the concatenation involves non-literal values
        if (tracker.isExpressionTainted(be.getLeft()) || tracker.isExpressionTainted(be.getRight())) {
            return true;
        }
        if (be.getLeft() instanceof NameExpr || be.getRight() instanceof NameExpr) {
            return true;
        }
        if (be.getLeft() instanceof MethodCallExpr || be.getRight() instanceof MethodCallExpr) {
            return true;
        }
        if (be.getLeft() instanceof BinaryExpr) {
            return hasDynamicParts((BinaryExpr) be.getLeft(), tracker);
        }
        if (be.getRight() instanceof BinaryExpr) {
            return hasDynamicParts((BinaryExpr) be.getRight(), tracker);
        }
        return false;
    }

    static String getSnippet(String sourceCode, int line) {
        String[] lines = sourceCode.split("\n");
        if (line < 1 || line > lines.length) return "";
        int start = Math.max(0, line - 2);
        int end = Math.min(lines.length, line + 2);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < end; i++) {
            sb.append(lines[i]).append("\n");
        }
        return sb.toString().trim();
    }
}
