package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class XssRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-XSS-001"; }
    @Override public String getCategory() { return "Cross-Site Scripting (XSS)"; }

    private static final Set<String> OUTPUT_METHODS = new HashSet<>(Arrays.asList(
        "write", "println", "print", "append", "format",
        "sendError", "setHeader", "addHeader",
        "addAttribute", "addObject", "addFlashAttribute"
    ));

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            TaintTracker lt = new TaintTracker();
            lt.analyzeMethod(method, filePath);

            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // Response writer output
                if (OUTPUT_METHODS.contains(name)) {
                    mce.getScope().ifPresent(scope -> {
                        String scopeStr = scope.toString().toLowerCase();
                        boolean isResponseOutput = scopeStr.contains("writer") || scopeStr.contains("response") ||
                            scopeStr.contains("out") || scopeStr.contains("output") || scopeStr.contains("getwriter");

                        // Also check for getWriter() chain
                        if (scope instanceof MethodCallExpr) {
                            String scopeMethod = ((MethodCallExpr) scope).getNameAsString();
                            if (scopeMethod.equals("getWriter") || scopeMethod.equals("getOutputStream")) {
                                isResponseOutput = true;
                            }
                        }

                        if (isResponseOutput) {
                            for (Expression arg : mce.getArguments()) {
                                if (lt.isExpressionTainted(arg)) {
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Cross-Site Scripting (XSS)")
                                        .severity("High")
                                        .title("Reflected XSS via response output")
                                        .description("User input is written directly to the HTTP response without encoding, enabling XSS attacks.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-79").owaspCategory("A03:2021 - Injection")
                                        .recommendation("Encode all user input before writing to response. Use OWASP Java Encoder or HtmlUtils.htmlEscape().")
                                        .confidence("High")
                                        .build());
                                } else if (arg instanceof BinaryExpr && containsGetParameter((BinaryExpr) arg)) {
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Cross-Site Scripting (XSS)")
                                        .severity("High")
                                        .title("Reflected XSS via direct parameter output")
                                        .description("Request parameter is concatenated into response output without encoding.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-79").owaspCategory("A03:2021 - Injection")
                                        .recommendation("Use output encoding: HtmlUtils.htmlEscape() or OWASP Java Encoder.")
                                        .confidence("High")
                                        .build());
                                }
                            }
                        }
                    });
                }

                // Spring ModelAndView / Model attribute with tainted data
                if ((name.equals("addAttribute") || name.equals("addObject")) && mce.getArguments().size() >= 2) {
                    Expression valueArg = mce.getArgument(1);
                    if (lt.isExpressionTainted(valueArg)) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("Cross-Site Scripting (XSS)")
                            .severity("Medium")
                            .title("Stored/Reflected XSS via Spring Model attribute")
                            .description("Tainted user input is added to the Model without encoding. If the template does not escape it, XSS is possible.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-79").owaspCategory("A03:2021 - Injection")
                            .recommendation("Ensure the view template escapes this value (Thymeleaf th:text auto-escapes, JSP needs c:out).")
                            .confidence("Medium")
                            .build());
                    }
                }
            });
        });

        return vulns;
    }

    private boolean containsGetParameter(BinaryExpr be) {
        String s = be.toString();
        return s.contains("getParameter") || s.contains("getHeader") || s.contains("getQueryString");
    }
}
