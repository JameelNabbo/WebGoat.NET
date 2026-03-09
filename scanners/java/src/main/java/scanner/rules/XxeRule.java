package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class XxeRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-XXE-001"; }
    @Override public String getCategory() { return "XML External Entity (XXE)"; }

    private static final Set<String> XML_PARSER_TYPES = new HashSet<>(Arrays.asList(
        "DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory",
        "TransformerFactory", "SchemaFactory", "SAXBuilder",
        "SAXReader", "XMLReader", "Digester"
    ));

    private static final Set<String> SAFE_FEATURES = new HashSet<>(Arrays.asList(
        "FEATURE_SECURE_PROCESSING",
        "disallow-doctype-decl",
        "external-general-entities",
        "external-parameter-entities",
        "load-external-dtd"
    ));

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            String methodStr = method.toString();

            // Find XML parser factory instantiations
            method.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                if (name.equals("newInstance") || name.equals("newFactory")) {
                    mce.getScope().ifPresent(scope -> {
                        String scopeStr = scope.toString();
                        if (XML_PARSER_TYPES.contains(scopeStr)) {
                            // Check if security features are set in the method
                            boolean hasSecureConfig = false;
                            for (String feature : SAFE_FEATURES) {
                                if (methodStr.contains(feature)) {
                                    hasSecureConfig = true;
                                    break;
                                }
                            }
                            if (methodStr.contains("setExpandEntityReferences") && methodStr.contains("false")) {
                                hasSecureConfig = true;
                            }

                            if (!hasSecureConfig) {
                                vulns.add(VulnerabilityReport.builder()
                                    .category("XML External Entity (XXE)")
                                    .severity("High")
                                    .title("XXE vulnerability: " + scopeStr + " without secure configuration")
                                    .description(scopeStr + " is created without disabling external entity processing. " +
                                        "An attacker can read local files, perform SSRF, or cause denial of service.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-611").owaspCategory("A05:2021 - Security Misconfiguration")
                                    .recommendation("Disable external entities: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)")
                                    .confidence("High")
                                    .build());
                            }
                        }
                    });
                }

                // Direct parse calls without checking config
                if (name.equals("parse") && mce.getScope().isPresent()) {
                    String scopeStr = mce.getScope().get().toString().toLowerCase();
                    if (scopeStr.contains("xmldecoder") || scopeStr.contains("unmarshaller")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("XML External Entity (XXE)")
                            .severity("High")
                            .title("Potential XXE via XML parsing")
                            .description("XML parsing detected. Ensure external entity processing is disabled.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-611").owaspCategory("A05:2021 - Security Misconfiguration")
                            .recommendation("Configure XML parsers to disable DTDs and external entities before parsing.")
                            .confidence("Medium")
                            .build());
                    }
                }
            });
        });

        return vulns;
    }
}
