package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

public class DeserializationRule implements ScanRule {
    @Override public String getRuleId() { return "JAVA-DESER-001"; }
    @Override public String getCategory() { return "Insecure Deserialization"; }

    @Override
    public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        cu.findAll(MethodCallExpr.class).forEach(mce -> {
            String name = mce.getNameAsString();
            int line = mce.getBegin().map(p -> p.line).orElse(0);

            // ObjectInputStream.readObject()
            if (name.equals("readObject") || name.equals("readUnshared")) {
                vulns.add(VulnerabilityReport.builder()
                    .category("Insecure Deserialization")
                    .severity("Critical")
                    .title("Insecure Java deserialization via " + name + "()")
                    .description("Java native deserialization (ObjectInputStream." + name + ") of untrusted data can lead to remote code execution. " +
                        "Known gadget chains in common libraries (Apache Commons, Spring, etc.) can be exploited.")
                    .filePath(filePath).lineNumber(line)
                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                    .cweId("CWE-502").owaspCategory("A08:2021 - Software and Data Integrity Failures")
                    .recommendation("Avoid Java native deserialization. Use JSON/XML with safe parsers. If unavoidable, use ObjectInputFilter (Java 9+) or Apache Commons IO ValidatingObjectInputStream.")
                    .confidence("High")
                    .build());
            }

            // XMLDecoder
            if (name.equals("readObject") && mce.getScope().map(s -> s.toString().contains("XMLDecoder") || s.toString().contains("xmlDecoder")).orElse(false)) {
                vulns.add(VulnerabilityReport.builder()
                    .category("Insecure Deserialization")
                    .severity("Critical")
                    .title("XMLDecoder deserialization vulnerability")
                    .description("XMLDecoder can execute arbitrary code during deserialization. It should never process untrusted input.")
                    .filePath(filePath).lineNumber(line)
                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                    .cweId("CWE-502").owaspCategory("A08:2021 - Software and Data Integrity Failures")
                    .recommendation("Replace XMLDecoder with a safe XML parser like Jackson or JAXB.")
                    .confidence("High")
                    .build());
            }

            // readValue / deserialize with untrusted type info
            if (name.equals("readValue") || name.equals("deserialize")) {
                // Check for enableDefaultTyping() or @JsonTypeInfo
                String methodBody = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString()).orElse("");
                if (methodBody.contains("enableDefaultTyping") || methodBody.contains("JsonTypeInfo")) {
                    vulns.add(VulnerabilityReport.builder()
                        .category("Insecure Deserialization")
                        .severity("High")
                        .title("Jackson polymorphic deserialization vulnerability")
                        .description("Jackson with default typing enabled or @JsonTypeInfo allows arbitrary class instantiation.")
                        .filePath(filePath).lineNumber(line)
                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                        .cweId("CWE-502").owaspCategory("A08:2021 - Software and Data Integrity Failures")
                        .recommendation("Avoid enableDefaultTyping(). Use @JsonTypeInfo with a closed set of types and PolymorphicTypeValidator.")
                        .confidence("Medium")
                        .build());
                }
            }
        });

        // Check for ObjectCreationExpr of dangerous types
        cu.findAll(ObjectCreationExpr.class).forEach(oce -> {
            String type = oce.getTypeAsString();
            if (type.equals("ObjectInputStream") || type.equals("XMLDecoder")) {
                int line = oce.getBegin().map(p -> p.line).orElse(0);
                vulns.add(VulnerabilityReport.builder()
                    .category("Insecure Deserialization")
                    .severity("High")
                    .title("Dangerous deserialization class instantiated: " + type)
                    .description(type + " is created, which can lead to remote code execution if processing untrusted data.")
                    .filePath(filePath).lineNumber(line)
                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                    .cweId("CWE-502").owaspCategory("A08:2021 - Software and Data Integrity Failures")
                    .recommendation("Use safe alternatives like JSON parsing with Jackson or Protocol Buffers.")
                    .confidence("Medium")
                    .build());
            }
        });

        return vulns;
    }
}
