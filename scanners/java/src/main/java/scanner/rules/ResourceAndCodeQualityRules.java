package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;

/**
 * Resource management and code quality rules:
 * - Resource Leak (CWE-404)
 * - Null Pointer Dereference (CWE-476)
 * - Race Conditions (CWE-362)
 * - Information Disclosure (CWE-200)
 * - Missing Input Validation (CWE-20)
 * - File Upload Issues (CWE-434)
 */
public class ResourceAndCodeQualityRules {

    // ===== RESOURCE LEAK =====
    public static class ResourceLeakRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-RES-001"; }
        @Override public String getCategory() { return "Resource Leak"; }

        private static final Set<String> CLOSEABLE_TYPES = new HashSet<>(Arrays.asList(
            "InputStream", "OutputStream", "FileInputStream", "FileOutputStream",
            "BufferedReader", "BufferedWriter", "FileReader", "FileWriter",
            "Connection", "Statement", "PreparedStatement", "ResultSet",
            "Socket", "ServerSocket", "DatagramSocket",
            "HttpURLConnection", "ObjectInputStream", "ObjectOutputStream",
            "Scanner", "PrintWriter", "RandomAccessFile",
            "ByteArrayInputStream", "ByteArrayOutputStream",
            "DataInputStream", "DataOutputStream",
            "InputStreamReader", "OutputStreamWriter",
            "GZIPInputStream", "GZIPOutputStream",
            "ZipInputStream", "ZipOutputStream",
            "JarInputStream", "JarOutputStream",
            "Channel", "Selector"
        ));

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                method.findAll(VariableDeclarator.class).forEach(vd -> {
                    String typeName = vd.getTypeAsString();
                    // Check if the type is a closeable resource
                    boolean isCloseable = CLOSEABLE_TYPES.stream().anyMatch(t -> typeName.contains(t));

                    if (isCloseable && vd.getInitializer().isPresent()) {
                        Expression init = vd.getInitializer().get();
                        if (init instanceof ObjectCreationExpr || init instanceof MethodCallExpr) {
                            // Check if it is inside a try-with-resources
                            boolean inTryWithResources = vd.findAncestor(TryStmt.class)
                                .map(tryStmt -> {
                                    // Check if this variable is declared in the resources part
                                    for (Expression res : tryStmt.getResources()) {
                                        if (res.toString().contains(vd.getNameAsString())) {
                                            return true;
                                        }
                                    }
                                    return false;
                                }).orElse(false);

                            // Check if close() is called on this variable
                            boolean hasClosed = method.findAll(MethodCallExpr.class).stream()
                                .anyMatch(mce -> mce.getNameAsString().equals("close") &&
                                    mce.getScope().map(s -> s.toString().equals(vd.getNameAsString())).orElse(false));

                            if (!inTryWithResources && !hasClosed) {
                                int line = vd.getBegin().map(p -> p.line).orElse(0);
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Resource Leak")
                                    .severity("Medium")
                                    .title("Resource leak: " + typeName + " not closed")
                                    .description("A " + typeName + " is opened but never closed in a finally block or try-with-resources. " +
                                        "This can lead to resource exhaustion (file handles, DB connections, memory).")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-404").owaspCategory("A04:2021 - Insecure Design")
                                    .recommendation("Use try-with-resources: try (" + typeName + " x = new " + typeName + "(...)) { ... }")
                                    .confidence("Medium")
                                    .build());
                            }
                        }
                    }
                });
            });

            return vulns;
        }
    }

    // ===== NULL POINTER DEREFERENCE =====
    public static class NullPointerRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-NULL-001"; }
        @Override public String getCategory() { return "Null Pointer Dereference"; }

        private static final Set<String> NULLABLE_METHODS = new HashSet<>(Arrays.asList(
            "get", "find", "findById", "findFirst", "findAny",
            "getParameter", "getAttribute", "getHeader",
            "getProperty", "getenv",
            "remove", "poll", "peek", "search"
        ));

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                Set<String> nullableVars = new HashSet<>();

                // Find variables assigned from nullable methods
                method.findAll(VariableDeclarator.class).forEach(vd -> {
                    vd.getInitializer().ifPresent(init -> {
                        if (init instanceof MethodCallExpr) {
                            String methodName = ((MethodCallExpr) init).getNameAsString();
                            if (NULLABLE_METHODS.contains(methodName)) {
                                nullableVars.add(vd.getNameAsString());
                            }
                        }
                    });
                });

                // Check for null-unsafe operations on nullable variables
                method.findAll(MethodCallExpr.class).forEach(mce -> {
                    mce.getScope().ifPresent(scope -> {
                        if (scope instanceof NameExpr) {
                            String varName = ((NameExpr) scope).getNameAsString();
                            if (nullableVars.contains(varName)) {
                                // Check if there is a null check before this usage
                                boolean hasNullCheck = false;
                                // Simple heuristic: check if varName + "!= null" appears before this line
                                int usageLine = mce.getBegin().map(p -> p.line).orElse(0);
                                String[] lines = sourceCode.split("\n");
                                for (int i = 0; i < Math.min(usageLine - 1, lines.length); i++) {
                                    if (lines[i].contains(varName + " != null") || lines[i].contains(varName + "!=null") ||
                                        lines[i].contains("Optional") || lines[i].contains(".isPresent()")) {
                                        hasNullCheck = true;
                                        break;
                                    }
                                }

                                if (!hasNullCheck) {
                                    int line = mce.getBegin().map(p -> p.line).orElse(0);
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Null Pointer Dereference")
                                        .severity("Medium")
                                        .title("Potential null pointer dereference: " + varName)
                                        .description("Variable '" + varName + "' may be null (returned from " +
                                            "a method that can return null) and is used without a null check.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-476").owaspCategory("A04:2021 - Insecure Design")
                                        .recommendation("Check for null before using the variable, or use Optional.map()/orElse().")
                                        .confidence("Medium")
                                        .build());
                                }
                            }
                        }
                    });
                });
            });

            return vulns;
        }
    }

    // ===== RACE CONDITIONS =====
    public static class RaceConditionRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-RACE-001"; }
        @Override public String getCategory() { return "Race Condition"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cls -> {
                boolean isSingleton = cls.getAnnotations().stream()
                    .anyMatch(a -> a.getNameAsString().equals("Singleton") || a.getNameAsString().equals("Component") ||
                        a.getNameAsString().equals("Service") || a.getNameAsString().equals("Controller") ||
                        a.getNameAsString().equals("RestController"));

                // Check for mutable fields in singleton-scoped beans
                if (isSingleton) {
                    cls.getFields().forEach(field -> {
                        boolean isStatic = field.isStatic();
                        boolean isFinal = field.isFinal();
                        boolean isVolatile = field.toString().contains("volatile");
                        boolean isAtomic = field.getCommonType().toString().startsWith("Atomic") ||
                            field.getCommonType().toString().contains("Concurrent");

                        if (!isFinal && !isVolatile && !isAtomic && !isStatic) {
                            String fieldType = field.getCommonType().toString();
                            // Skip common immutable/thread-safe types
                            if (!fieldType.equals("String") && !fieldType.contains("Logger") && !fieldType.contains("final")) {
                                // Check if field is mutated in methods
                                String fieldName = field.getVariables().get(0).getNameAsString();
                                boolean isMutated = cls.findAll(AssignExpr.class).stream()
                                    .anyMatch(ae -> ae.getTarget().toString().contains(fieldName));

                                if (isMutated) {
                                    int line = field.getBegin().map(p -> p.line).orElse(0);
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Race Condition")
                                        .severity("Medium")
                                        .title("Mutable shared state in singleton bean: " + fieldName)
                                        .description("A mutable field in a singleton-scoped Spring bean is modified, creating a race condition " +
                                            "when multiple threads access the bean concurrently.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-362").owaspCategory("A04:2021 - Insecure Design")
                                        .recommendation("Use thread-safe types (AtomicInteger, ConcurrentHashMap), synchronization, or request-scoped beans.")
                                        .confidence("Medium")
                                        .build());
                                }
                            }
                        }
                    });
                }

                // Check-then-act patterns (TOCTOU)
                cls.findAll(IfStmt.class).forEach(ifStmt -> {
                    String condition = ifStmt.getCondition().toString();
                    if (condition.contains(".exists()") || condition.contains(".isFile()") ||
                        condition.contains(".canRead()") || condition.contains(".canWrite()")) {
                        // Check if the then-block uses the same file
                        String thenStr = ifStmt.getThenStmt().toString();
                        if (thenStr.contains("new File") || thenStr.contains("delete") ||
                            thenStr.contains("createNewFile") || thenStr.contains("mkdir")) {
                            int line = ifStmt.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("Race Condition")
                                .severity("Medium")
                                .title("TOCTOU race condition on file operation")
                                .description("A file is checked (exists/canRead) and then operated on, creating a TOCTOU (Time of Check Time of Use) race condition.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-367").owaspCategory("A04:2021 - Insecure Design")
                                .recommendation("Use atomic file operations or file locking to prevent race conditions.")
                                .confidence("Medium")
                                .build());
                        }
                    }
                });
            });

            return vulns;
        }
    }

    // ===== INFORMATION DISCLOSURE =====
    public static class InfoDisclosureRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-INFO-001"; }
        @Override public String getCategory() { return "Information Disclosure"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(CatchClause.class).forEach(cc -> {
                String catchBody = cc.getBody().toString();
                String exceptionVar = cc.getParameter().getNameAsString();

                // Stack trace in response
                if (catchBody.contains("printStackTrace") ||
                    (catchBody.contains("getMessage") && (catchBody.contains("response") || catchBody.contains("writer") || catchBody.contains("print")))) {
                    int line = cc.getBegin().map(p -> p.line).orElse(0);

                    if (catchBody.contains("printStackTrace")) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("Information Disclosure")
                            .severity("Medium")
                            .title("Stack trace exposed via printStackTrace()")
                            .description("Stack traces are printed which may be visible in logs or responses, revealing internal application details.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-209").owaspCategory("A04:2021 - Insecure Design")
                            .recommendation("Use proper logging (logger.error()) instead of printStackTrace(). Never expose stack traces to end users.")
                            .confidence("Medium")
                            .build());
                    }
                }

                // Returning exception details to client
                if (catchBody.contains("getStackTrace") || catchBody.contains("toString()")) {
                    boolean returnsToClient = catchBody.contains("response") || catchBody.contains("return") ||
                        catchBody.contains("ResponseEntity") || catchBody.contains("sendError");
                    if (returnsToClient) {
                        int line = cc.getBegin().map(p -> p.line).orElse(0);
                        vulns.add(VulnerabilityReport.builder()
                            .category("Information Disclosure")
                            .severity("Medium")
                            .title("Exception details exposed to client")
                            .description("Exception information is returned in the HTTP response, potentially revealing internal implementation details.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-209").owaspCategory("A04:2021 - Insecure Design")
                            .recommendation("Return generic error messages to clients. Log detailed exceptions server-side.")
                            .confidence("Medium")
                            .build());
                    }
                }

                // Empty catch block (swallowed exception)
                if (cc.getBody().getStatements().isEmpty()) {
                    int line = cc.getBegin().map(p -> p.line).orElse(0);
                    vulns.add(VulnerabilityReport.builder()
                        .category("Information Disclosure")
                        .severity("Low")
                        .title("Empty catch block swallows exception")
                        .description("An empty catch block silently swallows the exception. This can hide errors and make debugging difficult, " +
                            "and may mask security-relevant failures.")
                        .filePath(filePath).lineNumber(line)
                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                        .cweId("CWE-390").owaspCategory("A09:2021 - Security Logging and Monitoring Failures")
                        .recommendation("At minimum, log the exception. Consider whether the exception indicates a security issue.")
                        .confidence("High")
                        .build());
                }
            });

            return vulns;
        }
    }

    // ===== MISSING INPUT VALIDATION =====
    public static class InputValidationRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-VALID-001"; }
        @Override public String getCategory() { return "Missing Input Validation"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                boolean isEndpoint = method.getAnnotations().stream()
                    .anyMatch(a -> {
                        String name = a.getNameAsString();
                        return name.equals("GetMapping") || name.equals("PostMapping") ||
                            name.equals("PutMapping") || name.equals("DeleteMapping") ||
                            name.equals("RequestMapping") || name.equals("PatchMapping");
                    });

                if (isEndpoint) {
                    for (com.github.javaparser.ast.body.Parameter param : method.getParameters()) {
                        boolean hasRequestBody = param.getAnnotations().stream()
                            .anyMatch(a -> a.getNameAsString().equals("RequestBody"));
                        boolean hasValid = param.getAnnotations().stream()
                            .anyMatch(a -> a.getNameAsString().equals("Valid") || a.getNameAsString().equals("Validated"));

                        if (hasRequestBody && !hasValid) {
                            int line = param.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("Missing Input Validation")
                                .severity("Medium")
                                .title("@RequestBody without @Valid annotation")
                                .description("A @RequestBody parameter lacks @Valid/@Validated annotation. " +
                                    "Bean validation constraints on the DTO will not be enforced.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-20").owaspCategory("A03:2021 - Injection")
                                .recommendation("Add @Valid or @Validated to @RequestBody parameters to enforce validation constraints.")
                                .confidence("High")
                                .build());
                        }
                    }
                }
            });

            return vulns;
        }
    }

    // ===== FILE UPLOAD ISSUES =====
    public static class FileUploadRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-UPLOAD-001"; }
        @Override public String getCategory() { return "File Upload Vulnerability"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                boolean handlesUpload = false;
                for (com.github.javaparser.ast.body.Parameter param : method.getParameters()) {
                    String paramType = param.getTypeAsString();
                    if (paramType.contains("MultipartFile") || paramType.contains("Part") ||
                        paramType.contains("CommonsMultipartFile")) {
                        handlesUpload = true;
                        break;
                    }
                }

                if (handlesUpload) {
                    String methodStr = method.toString();
                    boolean checksContentType = methodStr.contains("getContentType") || methodStr.contains("content-type") ||
                        methodStr.contains("ContentType");
                    boolean checksExtension = methodStr.contains("getOriginalFilename") && (methodStr.contains("endsWith") ||
                        methodStr.contains("extension") || methodStr.contains("suffix"));
                    boolean checksSize = methodStr.contains("getSize") || methodStr.contains("maxSize") ||
                        methodStr.contains("maxFileSize");

                    if (!checksContentType && !checksExtension) {
                        int line = method.getBegin().map(p -> p.line).orElse(0);
                        vulns.add(VulnerabilityReport.builder()
                            .category("File Upload Vulnerability")
                            .severity("High")
                            .title("File upload without type validation")
                            .description("File upload handler does not validate file type (extension or content type). " +
                                "An attacker can upload malicious files (e.g., web shells, malware).")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-434").owaspCategory("A04:2021 - Insecure Design")
                            .recommendation("Validate file extension against an allowlist. Check content type. Scan uploaded files for malware. " +
                                "Store files outside the web root with randomized names.")
                            .confidence("High")
                            .build());
                    }

                    if (!checksSize) {
                        int line = method.getBegin().map(p -> p.line).orElse(0);
                        vulns.add(VulnerabilityReport.builder()
                            .category("File Upload Vulnerability")
                            .severity("Medium")
                            .title("File upload without size validation")
                            .description("File upload handler does not validate file size, enabling denial-of-service via large file uploads.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-400").owaspCategory("A04:2021 - Insecure Design")
                            .recommendation("Set maximum file size limits both in configuration and in code validation.")
                            .confidence("Medium")
                            .build());
                    }

                    // Check for path traversal in filename
                    if (methodStr.contains("getOriginalFilename") && !methodStr.contains("normalize") &&
                        !methodStr.contains("stripPath") && !methodStr.contains("getFileName")) {
                        int line = method.getBegin().map(p -> p.line).orElse(0);
                        vulns.add(VulnerabilityReport.builder()
                            .category("File Upload Vulnerability")
                            .severity("High")
                            .title("File upload path traversal via original filename")
                            .description("The original filename from the upload is used without path normalization, enabling path traversal.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-22").owaspCategory("A01:2021 - Broken Access Control")
                            .recommendation("Sanitize filenames: strip path separators, use UUID-based names, validate against traversal patterns.")
                            .confidence("Medium")
                            .build());
                    }
                }
            });

            return vulns;
        }
    }
}
