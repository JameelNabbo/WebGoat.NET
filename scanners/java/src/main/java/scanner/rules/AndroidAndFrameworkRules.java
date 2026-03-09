package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

/**
 * Framework-specific security rules:
 * - Android Security
 * - Struts/OGNL Injection
 * - Hibernate HQL Injection
 * - Servlet Security
 */
public class AndroidAndFrameworkRules {

    // ===== ANDROID SECURITY =====
    public static class AndroidSecurityRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-ANDROID-001"; }
        @Override public String getCategory() { return "Android Security"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // WebView JavaScript enabled
                if (name.equals("setJavaScriptEnabled")) {
                    for (Expression arg : mce.getArguments()) {
                        if (arg.toString().equals("true")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Android Security")
                                .severity("High")
                                .title("WebView JavaScript enabled")
                                .description("JavaScript is enabled in WebView, which can lead to XSS attacks if loading untrusted content.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-79").owaspCategory("A03:2021 - Injection")
                                .recommendation("Only enable JavaScript if strictly necessary. Validate all URLs loaded in WebView.")
                                .confidence("High")
                                .build());
                        }
                    }
                }

                // WebView file access
                if (name.equals("setAllowFileAccess") || name.equals("setAllowFileAccessFromFileURLs") ||
                    name.equals("setAllowUniversalAccessFromFileURLs")) {
                    for (Expression arg : mce.getArguments()) {
                        if (arg.toString().equals("true")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Android Security")
                                .severity("High")
                                .title("WebView file access enabled: " + name)
                                .description("WebView file access allows reading local files, which can be exploited to steal sensitive data.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-200").owaspCategory("A01:2021 - Broken Access Control")
                                .recommendation("Disable file access in WebView unless absolutely required. Use setAllowFileAccess(false).")
                                .confidence("High")
                                .build());
                        }
                    }
                }

                // addJavascriptInterface
                if (name.equals("addJavascriptInterface")) {
                    vulns.add(VulnerabilityReport.builder()
                        .category("Android Security")
                        .severity("High")
                        .title("WebView JavaScript interface exposed")
                        .description("addJavascriptInterface() exposes Java objects to JavaScript, enabling RCE on Android < 4.2 " +
                            "and potential data theft on all versions if loading untrusted content.")
                        .filePath(filePath).lineNumber(line)
                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                        .cweId("CWE-749").owaspCategory("A04:2021 - Insecure Design")
                        .recommendation("Use @JavascriptInterface annotation (API 17+). Minimize exposed methods. Only load trusted content.")
                        .confidence("High")
                        .build());
                }

                // Insecure SharedPreferences for sensitive data
                if (name.equals("getSharedPreferences")) {
                    String context = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString().toLowerCase()).orElse("");
                    if (context.contains("password") || context.contains("token") || context.contains("secret") ||
                        context.contains("key") || context.contains("credential")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("Android Security")
                            .severity("Medium")
                            .title("Sensitive data stored in SharedPreferences")
                            .description("SharedPreferences stores data in plain text XML. Sensitive data (passwords, tokens) " +
                                "can be read by other apps on rooted devices.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-922").owaspCategory("A04:2021 - Insecure Design")
                            .recommendation("Use Android Keystore or EncryptedSharedPreferences for sensitive data.")
                            .confidence("Medium")
                            .build());
                    }
                }

                // Exported components without permissions
                if (name.equals("setExported")) {
                    for (Expression arg : mce.getArguments()) {
                        if (arg.toString().equals("true")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Android Security")
                                .severity("Medium")
                                .title("Exported Android component without permission check")
                                .description("An Android component is explicitly exported, making it accessible to other apps. " +
                                    "Without proper permission checks, this can lead to intent spoofing or data theft.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-926").owaspCategory("A01:2021 - Broken Access Control")
                                .recommendation("Set exported=false unless external access is required. Add permission requirements.")
                                .confidence("Medium")
                                .build());
                        }
                    }
                }

                // Intent from external source without validation
                if (name.equals("getIntent") || name.equals("getStringExtra") || name.equals("getParcelableExtra")) {
                    TaintTracker lt = new TaintTracker();
                    String methodContext = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString()).orElse("");
                    if (!methodContext.contains("validate") && !methodContext.contains("sanitize") &&
                        !methodContext.contains("check")) {
                        // Only report if used in sensitive context
                        if (methodContext.contains("query") || methodContext.contains("execute") ||
                            methodContext.contains("startActivity") || methodContext.contains("sendBroadcast")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Android Security")
                                .severity("Medium")
                                .title("Unvalidated Intent data used in sensitive operation")
                                .description("Data from an Intent is used without validation in a potentially sensitive operation.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-20").owaspCategory("A03:2021 - Injection")
                                .recommendation("Validate all data received from Intents before using it in sensitive operations.")
                                .confidence("Medium")
                                .build());
                        }
                    }
                }
            });

            return vulns;
        }
    }

    // ===== STRUTS/OGNL INJECTION =====
    public static class StrutsOgnlRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-STRUTS-001"; }
        @Override public String getCategory() { return "Struts OGNL Injection"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // OGNL.getValue/setValue with user input
                if (name.equals("getValue") || name.equals("setValue") || name.equals("compileExpression")) {
                    String scopeStr = mce.getScope().map(Expression::toString).orElse("").toLowerCase();
                    if (scopeStr.contains("ognl") || scopeStr.contains("Ognl")) {
                        TaintTracker lt = new TaintTracker();
                        MethodDeclaration method = mce.findAncestor(MethodDeclaration.class).orElse(null);
                        if (method != null) {
                            lt.analyzeMethod(method, filePath);
                            for (Expression arg : mce.getArguments()) {
                                if (lt.isExpressionTainted(arg) || arg instanceof BinaryExpr) {
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Struts OGNL Injection")
                                        .severity("Critical")
                                        .title("OGNL Injection via " + name + "()")
                                        .description("User input is evaluated as an OGNL expression. This enables remote code execution " +
                                            "similar to CVE-2017-5638 (Apache Struts).")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-917").owaspCategory("A03:2021 - Injection")
                                        .recommendation("Never pass user input to OGNL evaluation. Update Struts to latest version.")
                                        .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                        .build());
                                }
                            }
                        }
                    }
                }
            });

            // Check for ActionForm without validation
            cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
                boolean extendsActionForm = cls.getExtendedTypes().stream()
                    .anyMatch(t -> t.getNameAsString().contains("ActionForm") || t.getNameAsString().contains("DynaActionForm"));

                if (extendsActionForm) {
                    boolean hasValidate = cls.getMethods().stream()
                        .anyMatch(m -> m.getNameAsString().equals("validate"));

                    if (!hasValidate) {
                        int line = cls.getBegin().map(p -> p.line).orElse(0);
                        vulns.add(VulnerabilityReport.builder()
                            .category("Struts OGNL Injection")
                            .severity("Medium")
                            .title("ActionForm without validate() method")
                            .description("Struts ActionForm subclass does not override validate(), allowing mass assignment of all form fields.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-915").owaspCategory("A04:2021 - Insecure Design")
                            .recommendation("Override validate() to check all input fields. Consider migrating to Struts 2+ with proper validation.")
                            .confidence("Medium")
                            .build());
                    }
                }
            });

            return vulns;
        }
    }

    // ===== HIBERNATE HQL INJECTION =====
    public static class HibernateHqlRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-HIB-001"; }
        @Override public String getCategory() { return "Hibernate HQL Injection"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                TaintTracker lt = new TaintTracker();
                lt.analyzeMethod(method, filePath);

                method.findAll(MethodCallExpr.class).forEach(mce -> {
                    String name = mce.getNameAsString();
                    int line = mce.getBegin().map(p -> p.line).orElse(0);

                    // createQuery with string concatenation
                    if (name.equals("createQuery") || name.equals("createSQLQuery") || name.equals("createNativeQuery")) {
                        for (Expression arg : mce.getArguments()) {
                            if (arg instanceof BinaryExpr) {
                                BinaryExpr be = (BinaryExpr) arg;
                                if (be.getOperator() == BinaryExpr.Operator.PLUS) {
                                    boolean hasDynamic = lt.isExpressionTainted(arg) ||
                                        containsVariable(be);
                                    if (hasDynamic) {
                                        vulns.add(VulnerabilityReport.builder()
                                            .category("Hibernate HQL Injection")
                                            .severity("Critical")
                                            .title("HQL/SQL Injection via " + name + "() with string concatenation")
                                            .description("User input is concatenated into a Hibernate query. This allows " +
                                                "HQL injection attacks to bypass security, extract data, or modify records.")
                                            .filePath(filePath).lineNumber(line)
                                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                            .cweId("CWE-89").owaspCategory("A03:2021 - Injection")
                                            .recommendation("Use named parameters: createQuery(\"FROM User WHERE name = :name\").setParameter(\"name\", input)")
                                            .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                            .build());
                                    }
                                }
                            }
                        }
                    }

                    // Criteria API with unvalidated input
                    if (name.equals("add") && mce.getScope().isPresent()) {
                        String scopeStr = mce.getScope().get().toString().toLowerCase();
                        if (scopeStr.contains("criteria") || scopeStr.contains("restriction")) {
                            for (Expression arg : mce.getArguments()) {
                                if (arg instanceof MethodCallExpr) {
                                    MethodCallExpr restrictionCall = (MethodCallExpr) arg;
                                    String restrictionName = restrictionCall.getNameAsString();
                                    if (restrictionName.equals("sqlRestriction") || restrictionName.equals("sql")) {
                                        for (Expression sqlArg : restrictionCall.getArguments()) {
                                            if (sqlArg instanceof BinaryExpr && lt.isExpressionTainted(sqlArg)) {
                                                vulns.add(VulnerabilityReport.builder()
                                                    .category("Hibernate HQL Injection")
                                                    .severity("Critical")
                                                    .title("SQL Injection via Hibernate sqlRestriction()")
                                                    .description("User input in Hibernate Restrictions.sqlRestriction() enables direct SQL injection.")
                                                    .filePath(filePath).lineNumber(line)
                                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                                    .cweId("CWE-89").owaspCategory("A03:2021 - Injection")
                                                    .recommendation("Avoid sqlRestriction(). Use Criteria API methods with parameterized values.")
                                                    .confidence("High")
                                                    .build());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            });

            return vulns;
        }

        private boolean containsVariable(BinaryExpr be) {
            if (be.getLeft() instanceof NameExpr || be.getRight() instanceof NameExpr) return true;
            if (be.getLeft() instanceof MethodCallExpr || be.getRight() instanceof MethodCallExpr) return true;
            if (be.getLeft() instanceof BinaryExpr) return containsVariable((BinaryExpr) be.getLeft());
            if (be.getRight() instanceof BinaryExpr) return containsVariable((BinaryExpr) be.getRight());
            return false;
        }
    }

    // ===== SERVLET SECURITY =====
    public static class ServletSecurityRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-SERVLET-001"; }
        @Override public String getCategory() { return "Servlet Security"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // Session fixation: no invalidate before creating new session
                if (name.equals("getSession")) {
                    String methodStr = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString()).orElse("");
                    if (methodStr.contains("login") || methodStr.contains("authenticate") || methodStr.contains("Login")) {
                        if (!methodStr.contains("invalidate")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Servlet Security")
                                .severity("Medium")
                                .title("Potential session fixation vulnerability")
                                .description("A new session is created during authentication without invalidating the old session. " +
                                    "An attacker can fixate a session ID before authentication.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-384").owaspCategory("A07:2021 - Identification and Authentication Failures")
                                .recommendation("Call session.invalidate() before creating a new session during authentication.")
                                .confidence("Medium")
                                .build());
                        }
                    }
                }

                // HttpOnly flag missing on cookies
                if (name.equals("addCookie")) {
                    String methodStr = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString()).orElse("");
                    if (!methodStr.contains("setHttpOnly(true)") && !methodStr.contains("httpOnly")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("Servlet Security")
                            .severity("Medium")
                            .title("Cookie without HttpOnly flag")
                            .description("A cookie is set without the HttpOnly flag. JavaScript can access this cookie, enabling XSS-based session theft.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-1004").owaspCategory("A05:2021 - Security Misconfiguration")
                            .recommendation("Set cookie.setHttpOnly(true) for session cookies and sensitive cookies.")
                            .confidence("Medium")
                            .build());
                    }

                    // Secure flag missing
                    if (!methodStr.contains("setSecure(true)")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("Servlet Security")
                            .severity("Low")
                            .title("Cookie without Secure flag")
                            .description("A cookie is set without the Secure flag. It will be transmitted over unencrypted HTTP connections.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-614").owaspCategory("A05:2021 - Security Misconfiguration")
                            .recommendation("Set cookie.setSecure(true) for all sensitive cookies.")
                            .confidence("Low")
                            .build());
                    }
                }
            });

            return vulns;
        }
    }
}
