package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class LdapInjectionRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-LDAP-001"; }
    @Override public String getCategory() { return "LDAP Injection"; }

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            TaintTracker lt = new TaintTracker();
            lt.analyzeMethod(method, filePath);

            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                if (name.equals("search") || name.equals("lookup") || name.equals("list") || name.equals("bind")) {
                    String scopeStr = mce.getScope().map(Expression::toString).orElse("").toLowerCase();
                    if (scopeStr.contains("context") || scopeStr.contains("dir") || scopeStr.contains("ldap") ||
                        scopeStr.contains("ctx") || scopeStr.contains("naming")) {
                        for (Expression arg : mce.getArguments()) {
                            if (lt.isExpressionTainted(arg) || isConcatWithInput(arg)) {
                                vulns.add(VulnerabilityReport.builder()
                                    .category("LDAP Injection")
                                    .severity("High")
                                    .title("LDAP Injection via " + name + "()")
                                    .description("User input is concatenated into an LDAP query. An attacker can modify the LDAP filter to bypass authentication or access unauthorized data.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-90").owaspCategory("A03:2021 - Injection")
                                    .recommendation("Use parameterized LDAP queries or escape special LDAP characters (*, (, ), \\, NUL).")
                                    .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                    .build());
                            }
                        }
                    }
                }
            });
        });

        return vulns;
    }

    private boolean isConcatWithInput(Expression expr) {
        if (expr instanceof BinaryExpr) {
            String s = expr.toString();
            return s.contains("getParameter") || s.contains("getHeader") || s.contains("username") || s.contains("userName");
        }
        return false;
    }
}
