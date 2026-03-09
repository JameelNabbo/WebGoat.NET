package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class LogInjectionRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-LOG-001"; }
    @Override public String getCategory() { return "Log Injection"; }

    private static final Set<String> LOG_METHODS = new HashSet<>(Arrays.asList(
        "info", "debug", "warn", "error", "trace", "fatal", "log"
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

                if (LOG_METHODS.contains(name)) {
                    String scopeStr = mce.getScope().map(Expression::toString).orElse("").toLowerCase();
                    if (scopeStr.contains("log") || scopeStr.contains("logger") || scopeStr.contains("LOG")) {
                        for (Expression arg : mce.getArguments()) {
                            // Check for string concatenation with user input
                            if (arg instanceof BinaryExpr && lt.isExpressionTainted(arg)) {
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Log Injection")
                                    .severity("Medium")
                                    .title("Log Injection via " + name + "()")
                                    .description("User input is logged without sanitization. An attacker can inject fake log entries, " +
                                        "forge log records, or exploit log viewers. In Log4j 2.x, this could enable JNDI injection (Log4Shell).")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-117").owaspCategory("A09:2021 - Security Logging and Monitoring Failures")
                                    .recommendation("Sanitize user input before logging: replace newlines, encode special characters. " +
                                        "Use parameterized logging (logger.info(\"User: {}\", input)) instead of string concatenation. " +
                                        "Update Log4j to 2.17+ to prevent JNDI injection.")
                                    .confidence("High")
                                    .build());
                            }
                        }
                    }
                }
            });
        });

        return vulns;
    }
}
