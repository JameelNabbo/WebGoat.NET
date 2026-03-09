package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

/**
 * Spring-specific security rules:
 * - SpEL Injection
 * - CORS Misconfiguration
 * - CSRF Disabled
 * - Actuator Exposure
 * - Mass Assignment (@ModelAttribute)
 * - Open Redirect
 */
public class SpringSecurityRules {

    // ===== SpEL INJECTION =====
    public static class SpelInjectionRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-SPRING-001"; }
        @Override public String getCategory() { return "Spring SpEL Injection"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                TaintTracker lt = new TaintTracker();
                lt.analyzeMethod(method, filePath);

                method.findAll(MethodCallExpr.class).forEach(mce -> {
                    String name = mce.getNameAsString();
                    int line = mce.getBegin().map(p -> p.line).orElse(0);

                    if (name.equals("parseExpression") || name.equals("parseRaw")) {
                        for (Expression arg : mce.getArguments()) {
                            if (lt.isExpressionTainted(arg) || arg instanceof BinaryExpr) {
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Spring SpEL Injection")
                                    .severity("Critical")
                                    .title("Spring Expression Language (SpEL) Injection")
                                    .description("User input is passed to SpEL parser, enabling remote code execution via expression evaluation.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-917").owaspCategory("A03:2021 - Injection")
                                    .recommendation("Never pass user input to SpEL parser. Use SimpleEvaluationContext instead of StandardEvaluationContext.")
                                    .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                    .build());
                            }
                        }
                    }
                });
            });

            return vulns;
        }
    }

    // ===== CORS MISCONFIGURATION =====
    public static class CorsMisconfigRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-SPRING-002"; }
        @Override public String getCategory() { return "CORS Misconfiguration"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // allowedOrigins("*")
                if (name.equals("allowedOrigins") || name.equals("addAllowedOrigin") || name.equals("allowedOriginPatterns")) {
                    for (Expression arg : mce.getArguments()) {
                        if (arg.toString().contains("\"*\"")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("CORS Misconfiguration")
                                .severity("Medium")
                                .title("CORS allows all origins (*)")
                                .description("CORS is configured to allow all origins, which can expose the API to cross-origin attacks.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-942").owaspCategory("A05:2021 - Security Misconfiguration")
                                .recommendation("Restrict CORS origins to specific trusted domains.")
                                .confidence("High")
                                .build());
                        }
                    }
                }

                // allowCredentials(true) with wildcard origin
                if (name.equals("allowCredentials")) {
                    String methodStr = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString()).orElse("");
                    if (methodStr.contains("\"*\"") && mce.getArguments().toString().contains("true")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("CORS Misconfiguration")
                            .severity("High")
                            .title("CORS allows credentials with wildcard origin")
                            .description("CORS is configured to allow credentials with all origins, enabling cookie theft.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-942").owaspCategory("A05:2021 - Security Misconfiguration")
                            .recommendation("Never combine allowCredentials(true) with wildcard origins.")
                            .confidence("High")
                            .build());
                    }
                }

                // @CrossOrigin annotation with wildcard
                if (name.equals("setHeader") || name.equals("addHeader")) {
                    if (mce.getArguments().size() >= 2) {
                        String headerName = mce.getArgument(0).toString();
                        String headerValue = mce.getArgument(1).toString();
                        if (headerName.contains("Access-Control-Allow-Origin") && headerValue.contains("\"*\"")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("CORS Misconfiguration")
                                .severity("Medium")
                                .title("CORS header Access-Control-Allow-Origin set to *")
                                .description("Manual CORS header allows all origins.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-942").owaspCategory("A05:2021 - Security Misconfiguration")
                                .recommendation("Set specific allowed origins instead of wildcard.")
                                .confidence("High")
                                .build());
                        }
                    }
                }
            });

            // @CrossOrigin annotation check
            cu.findAll(AnnotationExpr.class).forEach(ann -> {
                if (ann.getNameAsString().equals("CrossOrigin")) {
                    String annStr = ann.toString();
                    if (annStr.contains("\"*\"") || (!annStr.contains("origins") && !annStr.contains("value"))) {
                        int line = ann.getBegin().map(p -> p.line).orElse(0);
                        vulns.add(VulnerabilityReport.builder()
                            .category("CORS Misconfiguration")
                            .severity("Medium")
                            .title("@CrossOrigin allows all origins")
                            .description("@CrossOrigin without explicit origins allows all origins by default.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-942").owaspCategory("A05:2021 - Security Misconfiguration")
                            .recommendation("Specify explicit origins in @CrossOrigin annotation.")
                            .confidence("Medium")
                            .build());
                    }
                }
            });

            return vulns;
        }
    }

    // ===== CSRF DISABLED =====
    public static class CsrfDisabledRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-SPRING-003"; }
        @Override public String getCategory() { return "CSRF Protection Disabled"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // csrf().disable() or csrf(c -> c.disable())
                if (name.equals("disable")) {
                    String chain = getCallChain(mce);
                    if (chain.contains("csrf")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("CSRF Protection Disabled")
                            .severity("Medium")
                            .title("Spring Security CSRF protection disabled")
                            .description("CSRF protection is explicitly disabled. This allows cross-site request forgery attacks against authenticated users.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-352").owaspCategory("A01:2021 - Broken Access Control")
                            .recommendation("Enable CSRF protection for state-changing endpoints. Only disable for stateless REST APIs using token-based auth.")
                            .confidence("High")
                            .build());
                    }
                }

                // ignoringAntMatchers
                if (name.equals("ignoringAntMatchers") || name.equals("ignoringRequestMatchers")) {
                    String chain = getCallChain(mce);
                    if (chain.contains("csrf")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("CSRF Protection Disabled")
                            .severity("Low")
                            .title("CSRF protection excluded for some endpoints")
                            .description("CSRF protection is selectively disabled for certain URL patterns.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-352").owaspCategory("A01:2021 - Broken Access Control")
                            .recommendation("Review excluded endpoints to ensure they are truly stateless or have alternative CSRF protection.")
                            .confidence("Medium")
                            .build());
                    }
                }
            });

            return vulns;
        }

        private String getCallChain(MethodCallExpr mce) {
            StringBuilder chain = new StringBuilder();
            Expression current = mce;
            while (current instanceof MethodCallExpr) {
                chain.insert(0, ((MethodCallExpr) current).getNameAsString() + ".");
                current = ((MethodCallExpr) current).getScope().orElse(null);
            }
            return chain.toString();
        }
    }

    // ===== ACTUATOR EXPOSURE =====
    public static class ActuatorExposureRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-SPRING-004"; }
        @Override public String getCategory() { return "Actuator Endpoint Exposure"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            // Check for actuator-related patterns in source
            String[] lines = sourceCode.split("\n");
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                // management.endpoints.web.exposure.include=*
                if (line.contains("exposure") && line.contains("include") && line.contains("*")) {
                    vulns.add(VulnerabilityReport.builder()
                        .category("Actuator Endpoint Exposure")
                        .severity("High")
                        .title("All Spring Boot Actuator endpoints exposed")
                        .description("All actuator endpoints are exposed, including sensitive ones like /env, /heapdump, /beans. " +
                            "This can leak environment variables, secrets, and internal application state.")
                        .filePath(filePath).lineNumber(i + 1)
                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, i + 1))
                        .cweId("CWE-200").owaspCategory("A05:2021 - Security Misconfiguration")
                        .recommendation("Only expose necessary endpoints: health, info. Secure sensitive endpoints with authentication.")
                        .confidence("High")
                        .build());
                }
            }

            // Check for permitAll on actuator paths
            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                if (mce.getNameAsString().equals("permitAll")) {
                    String methodStr = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString()).orElse("");
                    if (methodStr.contains("actuator") || methodStr.contains("/actuator")) {
                        int line = mce.getBegin().map(p -> p.line).orElse(0);
                        vulns.add(VulnerabilityReport.builder()
                            .category("Actuator Endpoint Exposure")
                            .severity("High")
                            .title("Actuator endpoints accessible without authentication")
                            .description("Spring Boot Actuator endpoints are configured to permit all access without authentication.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-200").owaspCategory("A05:2021 - Security Misconfiguration")
                            .recommendation("Require authentication for actuator endpoints.")
                            .confidence("High")
                            .build());
                    }
                }
            });

            return vulns;
        }
    }

    // ===== MASS ASSIGNMENT =====
    public static class MassAssignmentRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-SPRING-005"; }
        @Override public String getCategory() { return "Mass Assignment"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                // Check for @ModelAttribute parameter without @InitBinder
                for (com.github.javaparser.ast.body.Parameter param : method.getParameters()) {
                    boolean hasModelAttribute = param.getAnnotations().stream()
                        .anyMatch(a -> a.getNameAsString().equals("ModelAttribute"));
                    boolean hasRequestBody = param.getAnnotations().stream()
                        .anyMatch(a -> a.getNameAsString().equals("RequestBody"));

                    if (hasModelAttribute || hasRequestBody) {
                        // Check if the class has @InitBinder or field-level validation
                        boolean hasInitBinder = cu.findAll(MethodDeclaration.class).stream()
                            .anyMatch(m -> m.getAnnotations().stream()
                                .anyMatch(a -> a.getNameAsString().equals("InitBinder")));

                        if (!hasInitBinder) {
                            int line = param.getBegin().map(p -> p.line).orElse(0);
                            String annName = hasModelAttribute ? "@ModelAttribute" : "@RequestBody";
                            vulns.add(VulnerabilityReport.builder()
                                .category("Mass Assignment")
                                .severity("Medium")
                                .title("Mass Assignment via " + annName + " without field restriction")
                                .description("The " + annName + " parameter binds all request fields to the model without " +
                                    "an @InitBinder to restrict allowed fields. An attacker may set unintended fields (e.g., role, isAdmin).")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-915").owaspCategory("A04:2021 - Insecure Design")
                                .recommendation("Use @InitBinder with setAllowedFields() or use DTOs with only the expected fields.")
                                .confidence("Medium")
                                .build());
                        }
                    }
                }
            });

            return vulns;
        }
    }

    // ===== OPEN REDIRECT =====
    public static class OpenRedirectRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-REDIR-001"; }
        @Override public String getCategory() { return "Open Redirect"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                TaintTracker lt = new TaintTracker();
                lt.analyzeMethod(method, filePath);

                method.findAll(MethodCallExpr.class).forEach(mce -> {
                    String name = mce.getNameAsString();
                    int line = mce.getBegin().map(p -> p.line).orElse(0);

                    // sendRedirect with user input
                    if (name.equals("sendRedirect")) {
                        for (Expression arg : mce.getArguments()) {
                            if (lt.isExpressionTainted(arg) || isConcatWithInput(arg)) {
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Open Redirect")
                                    .severity("Medium")
                                    .title("Open Redirect via sendRedirect()")
                                    .description("User-controlled input is used in sendRedirect(), allowing an attacker to redirect users to a malicious site.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-601").owaspCategory("A01:2021 - Broken Access Control")
                                    .recommendation("Validate redirect URLs against an allowlist. Only allow relative paths or known safe domains.")
                                    .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                    .build());
                            }
                        }
                    }

                    // Spring redirect: prefix
                    if (name.equals("redirect") || (method.toString().contains("redirect:") && lt.isExpressionTainted(mce))) {
                        // Check for "redirect:" + userInput pattern in return statements
                    }
                });

                // Check return statements for "redirect:" + tainted
                method.findAll(com.github.javaparser.ast.stmt.ReturnStmt.class).forEach(ret -> {
                    ret.getExpression().ifPresent(expr -> {
                        if (expr instanceof BinaryExpr) {
                            String exprStr = expr.toString();
                            if (exprStr.contains("redirect:") && lt.isExpressionTainted(expr)) {
                                int line = ret.getBegin().map(p -> p.line).orElse(0);
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Open Redirect")
                                    .severity("Medium")
                                    .title("Open Redirect via Spring redirect: prefix")
                                    .description("User input is appended to a Spring redirect URL, enabling open redirect attacks.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-601").owaspCategory("A01:2021 - Broken Access Control")
                                    .recommendation("Validate redirect targets. Use UriUtils and validate against allowlist.")
                                    .confidence("High")
                                    .build());
                            }
                        }
                    });
                });
            });

            return vulns;
        }

        private boolean isConcatWithInput(Expression expr) {
            if (expr instanceof BinaryExpr) {
                String s = expr.toString();
                return s.contains("getParameter") || s.contains("getHeader") || s.contains("url") || s.contains("redirect");
            }
            return false;
        }
    }
}
