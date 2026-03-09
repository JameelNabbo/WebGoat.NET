package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class SsrfRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-SSRF-001"; }
    @Override public String getCategory() { return "Server-Side Request Forgery (SSRF)"; }

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            TaintTracker lt = new TaintTracker();
            lt.analyzeMethod(method, filePath);

            // new URL(userInput)
            method.findAll(ObjectCreationExpr.class).forEach(oce -> {
                String type = oce.getTypeAsString();
                if (type.equals("URL") || type.equals("URI") || type.equals("HttpURLConnection")) {
                    for (Expression arg : oce.getArguments()) {
                        if (lt.isExpressionTainted(arg) || isConcatWithInput(arg)) {
                            int line = oce.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("Server-Side Request Forgery (SSRF)")
                                .severity("High")
                                .title("SSRF via " + type + " with user-controlled URL")
                                .description("User input controls the URL for a server-side request. An attacker can access internal services, cloud metadata, or scan internal networks.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-918").owaspCategory("A10:2021 - Server-Side Request Forgery")
                                .recommendation("Validate URLs against an allowlist of permitted hosts/schemes. Block private IP ranges and metadata endpoints.")
                                .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                .build());
                        }
                    }
                }
            });

            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // RestTemplate methods
                if (name.equals("getForObject") || name.equals("getForEntity") || name.equals("postForObject") ||
                    name.equals("postForEntity") || name.equals("exchange") || name.equals("execute")) {
                    if (mce.getArguments().size() > 0) {
                        Expression urlArg = mce.getArgument(0);
                        if (lt.isExpressionTainted(urlArg) || isConcatWithInput(urlArg)) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Server-Side Request Forgery (SSRF)")
                                .severity("High")
                                .title("SSRF via RestTemplate." + name + "()")
                                .description("User-controlled URL passed to RestTemplate, enabling SSRF attacks.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-918").owaspCategory("A10:2021 - Server-Side Request Forgery")
                                .recommendation("Validate the URL against an allowlist. Use UriComponentsBuilder with validated components.")
                                .confidence(lt.isExpressionTainted(urlArg) ? "High" : "Medium")
                                .build());
                        }
                    }
                }

                // HttpClient
                if (name.equals("send") || name.equals("sendAsync")) {
                    mce.getScope().ifPresent(scope -> {
                        if (scope.toString().toLowerCase().contains("client") || scope.toString().toLowerCase().contains("http")) {
                            for (Expression arg : mce.getArguments()) {
                                if (lt.isExpressionTainted(arg)) {
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Server-Side Request Forgery (SSRF)")
                                        .severity("High")
                                        .title("SSRF via HttpClient." + name + "()")
                                        .description("User-controlled request passed to HttpClient.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-918").owaspCategory("A10:2021 - Server-Side Request Forgery")
                                        .recommendation("Validate all URL components against an allowlist.")
                                        .confidence("High")
                                        .build());
                                }
                            }
                        }
                    });
                }

                // openConnection / openStream on URL
                if (name.equals("openConnection") || name.equals("openStream")) {
                    mce.getScope().ifPresent(scope -> {
                        if (lt.isExpressionTainted(scope)) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Server-Side Request Forgery (SSRF)")
                                .severity("High")
                                .title("SSRF via URL." + name + "()")
                                .description("A URL constructed from user input is used to open a connection.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-918").owaspCategory("A10:2021 - Server-Side Request Forgery")
                                .recommendation("Validate URLs against an allowlist before opening connections.")
                                .confidence("High")
                                .build());
                        }
                    });
                }
            });
        });

        return vulns;
    }

    private boolean isConcatWithInput(Expression expr) {
        if (expr instanceof BinaryExpr) {
            String s = expr.toString();
            return s.contains("getParameter") || s.contains("getHeader") || s.contains("getPathInfo");
        }
        return false;
    }
}
