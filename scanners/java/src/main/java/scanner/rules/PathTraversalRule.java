package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class PathTraversalRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-PATH-001"; }
    @Override public String getCategory() { return "Path Traversal"; }

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            TaintTracker lt = new TaintTracker();
            lt.analyzeMethod(method, filePath);

            // new File(userInput)
            method.findAll(ObjectCreationExpr.class).forEach(oce -> {
                String type = oce.getTypeAsString();
                if (type.equals("File") || type.equals("FileInputStream") || type.equals("FileOutputStream") ||
                    type.equals("FileReader") || type.equals("FileWriter") || type.equals("RandomAccessFile")) {
                    for (Expression arg : oce.getArguments()) {
                        if (lt.isExpressionTainted(arg) || isConcatWithInput(arg)) {
                            int line = oce.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("Path Traversal")
                                .severity("High")
                                .title("Path Traversal via " + type + " constructor")
                                .description("User-controlled input is used to construct a file path. An attacker can use ../ sequences to access arbitrary files.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-22").owaspCategory("A01:2021 - Broken Access Control")
                                .recommendation("Validate and canonicalize file paths. Use Path.normalize() and verify the resolved path is within the expected directory.")
                                .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                .build());
                        }
                    }
                }
            });

            // Paths.get(), Path.of(), Path.resolve() with user input
            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                if (name.equals("get") || name.equals("of") || name.equals("resolve") || name.equals("resolveSibling")) {
                    String scopeStr = mce.getScope().map(Expression::toString).orElse("");
                    if (scopeStr.contains("Paths") || scopeStr.contains("Path") || scopeStr.contains("path")) {
                        for (Expression arg : mce.getArguments()) {
                            if (lt.isExpressionTainted(arg) || isConcatWithInput(arg)) {
                                int line = mce.getBegin().map(p -> p.line).orElse(0);
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Path Traversal")
                                    .severity("High")
                                    .title("Path Traversal via " + scopeStr + "." + name + "()")
                                    .description("User input is used in path construction, allowing directory traversal attacks.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-22").owaspCategory("A01:2021 - Broken Access Control")
                                    .recommendation("Canonicalize paths and verify they remain within the expected base directory.")
                                    .confidence(lt.isExpressionTainted(arg) ? "High" : "Medium")
                                    .build());
                            }
                        }
                    }
                }

                // getResource / getResourceAsStream
                if (name.equals("getResource") || name.equals("getResourceAsStream")) {
                    for (Expression arg : mce.getArguments()) {
                        if (lt.isExpressionTainted(arg)) {
                            int line = mce.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("Path Traversal")
                                .severity("Medium")
                                .title("Path Traversal via " + name + "()")
                                .description("User input controls resource loading path.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-22").owaspCategory("A01:2021 - Broken Access Control")
                                .recommendation("Use an allowlist of permitted resource paths.")
                                .confidence("Medium")
                                .build());
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
            return s.contains("getParameter") || s.contains("getHeader") ||
                   s.contains("getPathInfo") || s.contains("fileName");
        }
        return false;
    }
}
