package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class CodeInjectionRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-CODE-001"; }
    @Override public String getCategory() { return "Code Injection"; }

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            TaintTracker lt = new TaintTracker();
            lt.analyzeMethod(method, filePath);

            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                // ScriptEngine.eval()
                if (name.equals("eval")) {
                    mce.getScope().ifPresent(scope -> {
                        String s = scope.toString().toLowerCase();
                        if (s.contains("engine") || s.contains("script") || s.contains("nashorn") || s.contains("graalvm")) {
                            for (Expression arg : mce.getArguments()) {
                                if (lt.isExpressionTainted(arg) || arg instanceof BinaryExpr || arg instanceof NameExpr) {
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Code Injection")
                                        .severity("Critical")
                                        .title("Script Engine Code Injection via eval()")
                                        .description("User input is passed to ScriptEngine.eval(), allowing arbitrary code execution.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-94").owaspCategory("A03:2021 - Injection")
                                        .recommendation("Never pass user input to ScriptEngine.eval(). Use sandboxed execution or a safe expression parser.")
                                        .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                        .build());
                                    break;
                                }
                            }
                        }
                    });
                }

                // JNDI lookup
                if (name.equals("lookup")) {
                    for (Expression arg : mce.getArguments()) {
                        if (lt.isExpressionTainted(arg) || arg instanceof BinaryExpr) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Code Injection")
                                .severity("Critical")
                                .title("JNDI Injection via lookup()")
                                .description("User input flows into a JNDI lookup() call, enabling remote code execution (Log4Shell-style attack).")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-917").owaspCategory("A03:2021 - Injection")
                                .recommendation("Never pass user input to JNDI lookup(). Restrict JNDI protocols and remote code bases.")
                                .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                .build());
                        }
                    }
                }

                // Expression Language injection (SpEL, OGNL, EL)
                if (name.equals("parseExpression") || name.equals("getValue") || name.equals("evaluate")) {
                    for (Expression arg : mce.getArguments()) {
                        if (lt.isExpressionTainted(arg) || arg instanceof BinaryExpr) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Code Injection")
                                .severity("Critical")
                                .title("Expression Language Injection")
                                .description("User input is passed to an expression parser (" + name + "), enabling code execution.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-917").owaspCategory("A03:2021 - Injection")
                                .recommendation("Do not pass user input to expression parsers. Use SimpleEvaluationContext in Spring SpEL.")
                                .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                .build());
                        }
                    }
                }

                // Reflection-based injection
                if (name.equals("forName") || name.equals("loadClass") || name.equals("newInstance")) {
                    for (Expression arg : mce.getArguments()) {
                        if (lt.isExpressionTainted(arg)) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Code Injection")
                                .severity("High")
                                .title("Reflection-based Code Injection via " + name + "()")
                                .description("User input controls class loading/instantiation through reflection.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-470").owaspCategory("A03:2021 - Injection")
                                .recommendation("Never allow user input to control class names in reflection. Use a strict allowlist.")
                                .confidence("High")
                                .build());
                        }
                    }
                }
            });
        });

        return vulns;
    }
}
