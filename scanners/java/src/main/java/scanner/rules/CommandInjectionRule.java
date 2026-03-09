package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;

import java.util.*;

public class CommandInjectionRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-CMD-001"; }
    @Override public String getCategory() { return "Command Injection"; }

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            TaintTracker localTracker = new TaintTracker();
            localTracker.analyzeMethod(method, filePath);

            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String methodName = mce.getNameAsString();

                // Runtime.exec()
                if (methodName.equals("exec")) {
                    mce.getScope().ifPresent(scope -> {
                        String scopeStr = scope.toString();
                        if (scopeStr.contains("Runtime") || scopeStr.contains("runtime") ||
                            scopeStr.contains("getRuntime")) {
                            checkCommandArgs(mce, localTracker, filePath, sourceCode, vulns, "Runtime.exec()");
                        }
                    });
                }

                // ProcessBuilder.command() or constructor
                if (methodName.equals("command") || methodName.equals("start")) {
                    mce.getScope().ifPresent(scope -> {
                        if (scope.toString().contains("ProcessBuilder") || scope.toString().contains("processBuilder")) {
                            checkCommandArgs(mce, localTracker, filePath, sourceCode, vulns, "ProcessBuilder");
                        }
                    });
                }
            });

            // Check ProcessBuilder constructors
            method.findAll(ObjectCreationExpr.class).forEach(oce -> {
                if (oce.getTypeAsString().equals("ProcessBuilder")) {
                    for (Expression arg : oce.getArguments()) {
                        if (localTracker.isExpressionTainted(arg) || containsUserInput(arg)) {
                            int line = oce.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("Command Injection")
                                .severity("Critical")
                                .title("Command Injection via ProcessBuilder constructor")
                                .description("User-controlled input is passed to a ProcessBuilder constructor, allowing command injection.")
                                .filePath(filePath)
                                .lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-78")
                                .owaspCategory("A03:2021 - Injection")
                                .recommendation("Validate and sanitize all input before passing to ProcessBuilder. Use allowlists for permitted commands.")
                                .confidence(localTracker.isExpressionTainted(arg) ? "High" : "Medium")
                                .build());
                        }
                    }
                }
            });
        });

        return vulns;
    }

    private void checkCommandArgs(MethodCallExpr mce, TaintTracker tracker, String filePath,
                                   String sourceCode, List<VulnerabilityReport> vulns, String sinkName) {
        for (Expression arg : mce.getArguments()) {
            if (tracker.isExpressionTainted(arg) || containsUserInput(arg)) {
                int line = mce.getBegin().map(p -> p.line).orElse(0);
                vulns.add(VulnerabilityReport.builder()
                    .category("Command Injection")
                    .severity("Critical")
                    .title("Command Injection via " + sinkName)
                    .description("User-controlled input flows into " + sinkName + ". An attacker can execute arbitrary OS commands.")
                    .filePath(filePath)
                    .lineNumber(line)
                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                    .cweId("CWE-78")
                    .owaspCategory("A03:2021 - Injection")
                    .recommendation("Avoid executing OS commands with user input. If necessary, use strict allowlists and input validation.")
                    .confidence(tracker.isExpressionTainted(arg) ? "High" : "Medium")
                    .build());
            }
        }
    }

    private boolean containsUserInput(Expression expr) {
        if (expr instanceof BinaryExpr) {
            return containsUserInput(((BinaryExpr) expr).getLeft()) || containsUserInput(((BinaryExpr) expr).getRight());
        }
        if (expr instanceof MethodCallExpr) {
            MethodCallExpr mce = (MethodCallExpr) expr;
            String name = mce.getNameAsString();
            return name.equals("getParameter") || name.equals("getHeader") || name.equals("getQueryString") ||
                   name.equals("getPathInfo") || name.equals("readLine");
        }
        return false;
    }
}
