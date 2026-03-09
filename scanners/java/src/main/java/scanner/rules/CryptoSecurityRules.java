package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;
import java.util.*;
import java.util.regex.*;

/**
 * Combined rules for cryptographic and security issues:
 * - Hardcoded Secrets (CWE-798)
 * - Weak Cryptography (CWE-327)
 * - Insecure Random (CWE-330)
 * - Insecure TLS (CWE-295)
 * - JWT Issues (CWE-347)
 * - Timing Attacks (CWE-208)
 */
public class CryptoSecurityRules {

    // ===== HARDCODED SECRETS =====
    public static class HardcodedSecretsRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-SEC-001"; }
        @Override public String getCategory() { return "Hardcoded Secrets"; }

        private static final Pattern SECRET_PATTERN = Pattern.compile(
            "(password|passwd|pwd|secret|api_?key|apikey|access_?key|auth_?token|" +
            "private_?key|encryption_?key|signing_?key|jwt_?secret|db_?password|" +
            "database_?password|connection_?string|credentials?)",
            Pattern.CASE_INSENSITIVE
        );

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            // Check field declarations
            cu.findAll(FieldDeclaration.class).forEach(fd -> {
                for (VariableDeclarator vd : fd.getVariables()) {
                    String varName = vd.getNameAsString();
                    if (SECRET_PATTERN.matcher(varName).find()) {
                        vd.getInitializer().ifPresent(init -> {
                            if (init instanceof StringLiteralExpr) {
                                String value = ((StringLiteralExpr) init).getValue();
                                if (value.length() >= 4 && !value.contains("${") && !value.contains("#{") &&
                                    !value.equalsIgnoreCase("password") && !value.equalsIgnoreCase("secret") &&
                                    !value.contains("TODO") && !value.contains("CHANGE") && !value.contains("xxx")) {
                                    int line = vd.getBegin().map(p -> p.line).orElse(0);
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Hardcoded Secrets")
                                        .severity("High")
                                        .title("Hardcoded secret in variable: " + varName)
                                        .description("A secret value is hardcoded in the source code. This exposes credentials to anyone with access to the codebase.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-798").owaspCategory("A07:2021 - Identification and Authentication Failures")
                                        .recommendation("Store secrets in environment variables, a vault service (HashiCorp Vault, AWS Secrets Manager), or encrypted configuration files.")
                                        .confidence("High")
                                        .build());
                                }
                            }
                        });
                    }
                }
            });

            // Check variable declarations in methods
            cu.findAll(VariableDeclarator.class).forEach(vd -> {
                String varName = vd.getNameAsString();
                if (SECRET_PATTERN.matcher(varName).find()) {
                    vd.getInitializer().ifPresent(init -> {
                        if (init instanceof StringLiteralExpr) {
                            String value = ((StringLiteralExpr) init).getValue();
                            if (value.length() >= 4 && !value.contains("${") && !value.equalsIgnoreCase("password")) {
                                int line = vd.getBegin().map(p -> p.line).orElse(0);
                                // Avoid duplicates from field check
                                if (!vd.findAncestor(FieldDeclaration.class).isPresent()) {
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Hardcoded Secrets")
                                        .severity("High")
                                        .title("Hardcoded secret in local variable: " + varName)
                                        .description("A secret value is hardcoded in a local variable.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-798").owaspCategory("A07:2021 - Identification and Authentication Failures")
                                        .recommendation("Use environment variables or configuration management for secrets.")
                                        .confidence("High")
                                        .build());
                                }
                            }
                        }
                    });
                }
            });

            return vulns;
        }
    }

    // ===== WEAK CRYPTOGRAPHY =====
    public static class WeakCryptoRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-CRYPTO-001"; }
        @Override public String getCategory() { return "Weak Cryptography"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                int line = mce.getBegin().map(p -> p.line).orElse(0);

                if (name.equals("getInstance")) {
                    if (mce.getArguments().size() > 0) {
                        String arg = mce.getArgument(0).toString().replaceAll("\"", "").toUpperCase();

                        // Weak hash algorithms
                        if (arg.equals("MD5") || arg.equals("MD4") || arg.equals("MD2")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Weak Cryptography")
                                .severity("Medium")
                                .title("Weak hash algorithm: " + arg)
                                .description(arg + " is cryptographically broken and should not be used for security-sensitive operations.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-328").owaspCategory("A02:2021 - Cryptographic Failures")
                                .recommendation("Use SHA-256, SHA-384, or SHA-512 for hashing. For password hashing, use bcrypt, scrypt, or Argon2.")
                                .confidence("High")
                                .build());
                        }

                        if (arg.equals("SHA1") || arg.equals("SHA-1")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Weak Cryptography")
                                .severity("Medium")
                                .title("Deprecated hash algorithm: SHA-1")
                                .description("SHA-1 has known collision attacks and is deprecated for security use.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-328").owaspCategory("A02:2021 - Cryptographic Failures")
                                .recommendation("Use SHA-256 or stronger.")
                                .confidence("High")
                                .build());
                        }

                        // Weak encryption algorithms
                        if (arg.contains("DES") && !arg.contains("3DES") && !arg.contains("DESEDE")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Weak Cryptography")
                                .severity("High")
                                .title("Weak encryption algorithm: DES")
                                .description("DES uses 56-bit keys and can be brute-forced.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-327").owaspCategory("A02:2021 - Cryptographic Failures")
                                .recommendation("Use AES-256-GCM for symmetric encryption.")
                                .confidence("High")
                                .build());
                        }

                        if (arg.contains("RC4") || arg.contains("RC2") || arg.contains("BLOWFISH")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Weak Cryptography")
                                .severity("High")
                                .title("Weak encryption algorithm: " + arg)
                                .description(arg + " has known vulnerabilities and should not be used.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-327").owaspCategory("A02:2021 - Cryptographic Failures")
                                .recommendation("Use AES-256-GCM for encryption.")
                                .confidence("High")
                                .build());
                        }

                        // ECB mode
                        if (arg.contains("ECB")) {
                            vulns.add(VulnerabilityReport.builder()
                                .category("Weak Cryptography")
                                .severity("High")
                                .title("Insecure cipher mode: ECB")
                                .description("ECB mode encrypts identical blocks to identical ciphertext, leaking patterns in the data.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-327").owaspCategory("A02:2021 - Cryptographic Failures")
                                .recommendation("Use CBC with random IV, or preferably GCM mode for authenticated encryption.")
                                .confidence("High")
                                .build());
                        }
                    }
                }

                // Small key sizes
                if (name.equals("initialize") || name.equals("init")) {
                    for (Expression arg : mce.getArguments()) {
                        if (arg instanceof IntegerLiteralExpr) {
                            int keySize = Integer.parseInt(((IntegerLiteralExpr) arg).getValue());
                            if (keySize < 2048) {
                                String methodContext = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString().toLowerCase()).orElse("");
                                if (methodContext.contains("rsa") || methodContext.contains("keypairgenerator")) {
                                    vulns.add(VulnerabilityReport.builder()
                                        .category("Weak Cryptography")
                                        .severity("High")
                                        .title("Insufficient RSA key size: " + keySize + " bits")
                                        .description("RSA keys smaller than 2048 bits are considered insecure.")
                                        .filePath(filePath).lineNumber(line)
                                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                        .cweId("CWE-326").owaspCategory("A02:2021 - Cryptographic Failures")
                                        .recommendation("Use RSA key sizes of 2048 bits or larger, preferably 4096.")
                                        .confidence("High")
                                        .build());
                                }
                            }
                        }
                    }
                }
            });

            return vulns;
        }
    }

    // ===== INSECURE RANDOM =====
    public static class InsecureRandomRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-RAND-001"; }
        @Override public String getCategory() { return "Insecure Random"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(ObjectCreationExpr.class).forEach(oce -> {
                String type = oce.getTypeAsString();
                if (type.equals("Random")) {
                    String context = oce.findAncestor(MethodDeclaration.class).map(m -> m.toString().toLowerCase()).orElse("");
                    boolean securityContext = context.contains("token") || context.contains("password") ||
                        context.contains("secret") || context.contains("key") || context.contains("session") ||
                        context.contains("otp") || context.contains("nonce") || context.contains("salt") ||
                        context.contains("csrf") || context.contains("generate");

                    int line = oce.getBegin().map(p -> p.line).orElse(0);
                    vulns.add(VulnerabilityReport.builder()
                        .category("Insecure Random")
                        .severity(securityContext ? "High" : "Medium")
                        .title("Use of java.util.Random" + (securityContext ? " in security-sensitive context" : ""))
                        .description("java.util.Random uses a predictable PRNG. " +
                            (securityContext ? "In this security-sensitive context, an attacker can predict generated values." :
                            "If used for security purposes (tokens, keys, etc.), values can be predicted."))
                        .filePath(filePath).lineNumber(line)
                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                        .cweId("CWE-330").owaspCategory("A02:2021 - Cryptographic Failures")
                        .recommendation("Use java.security.SecureRandom for any security-sensitive random number generation.")
                        .confidence(securityContext ? "High" : "Medium")
                        .build());
                }
            });

            // Math.random() usage
            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                if (mce.getNameAsString().equals("random") &&
                    mce.getScope().map(s -> s.toString().equals("Math")).orElse(false)) {
                    String context = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString().toLowerCase()).orElse("");
                    boolean securityContext = context.contains("token") || context.contains("password") ||
                        context.contains("secret") || context.contains("key") || context.contains("session");

                    int line = mce.getBegin().map(p -> p.line).orElse(0);
                    vulns.add(VulnerabilityReport.builder()
                        .category("Insecure Random")
                        .severity(securityContext ? "High" : "Low")
                        .title("Use of Math.random()" + (securityContext ? " in security context" : ""))
                        .description("Math.random() uses java.util.Random internally and is not cryptographically secure.")
                        .filePath(filePath).lineNumber(line)
                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                        .cweId("CWE-330").owaspCategory("A02:2021 - Cryptographic Failures")
                        .recommendation("Use SecureRandom for security-sensitive random values.")
                        .confidence(securityContext ? "High" : "Low")
                        .build());
                }
            });

            return vulns;
        }
    }

    // ===== INSECURE TLS =====
    public static class InsecureTlsRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-TLS-001"; }
        @Override public String getCategory() { return "Insecure TLS Configuration"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            // TrustAllCerts / disabled certificate validation
            cu.findAll(MethodDeclaration.class).forEach(method -> {
                String methodStr = method.toString();
                String methodName = method.getNameAsString();
                int line = method.getBegin().map(p -> p.line).orElse(0);

                // TrustManager that trusts all
                if (methodName.equals("checkClientTrusted") || methodName.equals("checkServerTrusted")) {
                    if (method.getBody().isPresent() && method.getBody().get().getStatements().isEmpty()) {
                        vulns.add(VulnerabilityReport.builder()
                            .category("Insecure TLS Configuration")
                            .severity("Critical")
                            .title("TLS certificate validation disabled (TrustAll)")
                            .description("The TrustManager accepts all certificates without validation, enabling man-in-the-middle attacks.")
                            .filePath(filePath).lineNumber(line)
                            .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                            .cweId("CWE-295").owaspCategory("A07:2021 - Identification and Authentication Failures")
                            .recommendation("Use the default TrustManager or configure it with a proper trust store.")
                            .confidence("High")
                            .build());
                    }
                }

                // HostnameVerifier that returns true
                if (methodName.equals("verify") && method.getType().toString().equals("boolean")) {
                    if (method.getBody().isPresent()) {
                        String body = method.getBody().get().toString();
                        if (body.contains("return true") && body.trim().length() < 50) {
                            boolean isHostnameVerifier = method.findAncestor(ClassOrInterfaceDeclaration.class)
                                .map(c -> c.toString().contains("HostnameVerifier"))
                                .orElse(false);
                            if (isHostnameVerifier || methodStr.contains("hostname") || methodStr.contains("Hostname")) {
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Insecure TLS Configuration")
                                    .severity("Critical")
                                    .title("Hostname verification disabled")
                                    .description("HostnameVerifier always returns true, disabling hostname verification.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-295").owaspCategory("A07:2021 - Identification and Authentication Failures")
                                    .recommendation("Use the default HostnameVerifier or implement proper hostname verification.")
                                    .confidence("High")
                                    .build());
                            }
                        }
                    }
                }
            });

            // SSL/TLS version checks
            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                if (mce.getNameAsString().equals("getInstance") || mce.getNameAsString().equals("getContext")) {
                    for (Expression arg : mce.getArguments()) {
                        String argStr = arg.toString().replaceAll("\"", "").toUpperCase();
                        if (argStr.equals("SSL") || argStr.equals("SSLV2") || argStr.equals("SSLV3") ||
                            argStr.equals("TLS") || argStr.equals("TLSV1") || argStr.equals("TLSV1.0") ||
                            argStr.equals("TLSV1.1")) {
                            int line = mce.getBegin().map(p -> p.line).orElse(0);
                            vulns.add(VulnerabilityReport.builder()
                                .category("Insecure TLS Configuration")
                                .severity("High")
                                .title("Deprecated TLS/SSL protocol version: " + argStr)
                                .description("Using deprecated protocol version that has known vulnerabilities.")
                                .filePath(filePath).lineNumber(line)
                                .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                .cweId("CWE-326").owaspCategory("A02:2021 - Cryptographic Failures")
                                .recommendation("Use TLSv1.2 or TLSv1.3 only.")
                                .confidence("High")
                                .build());
                        }
                    }
                }
            });

            return vulns;
        }
    }

    // ===== JWT ISSUES =====
    public static class JwtIssuesRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-JWT-001"; }
        @Override public String getCategory() { return "JWT Security Issues"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();
            String src = sourceCode.toLowerCase();

            // Weak JWT secret
            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                String name = mce.getNameAsString();
                if (name.equals("sign") || name.equals("signWith") || name.equals("hmacShaKeyFor")) {
                    for (Expression arg : mce.getArguments()) {
                        if (arg instanceof StringLiteralExpr) {
                            String secret = ((StringLiteralExpr) arg).getValue();
                            if (secret.length() < 32) {
                                int line = mce.getBegin().map(p -> p.line).orElse(0);
                                vulns.add(VulnerabilityReport.builder()
                                    .category("JWT Security Issues")
                                    .severity("High")
                                    .title("Weak JWT signing secret (< 256 bits)")
                                    .description("The JWT signing secret is too short (" + secret.length() * 8 + " bits). Weak secrets can be brute-forced.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-326").owaspCategory("A02:2021 - Cryptographic Failures")
                                    .recommendation("Use a secret of at least 256 bits (32 characters) for HMAC.")
                                    .confidence("High")
                                    .build());
                            }
                        }
                    }
                }
            });

            // Check for "none" algorithm usage
            String[] lines = sourceCode.split("\n");
            for (int i = 0; i < lines.length; i++) {
                String lineStr = lines[i].toLowerCase();
                if (lineStr.contains("\"none\"") && (src.contains("jwt") || src.contains("algorithm") || src.contains("alg"))) {
                    vulns.add(VulnerabilityReport.builder()
                        .category("JWT Security Issues")
                        .severity("Critical")
                        .title("JWT 'none' algorithm potentially allowed")
                        .description("The 'none' algorithm string is present in JWT-related code. This could allow token forgery.")
                        .filePath(filePath).lineNumber(i + 1)
                        .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, i + 1))
                        .cweId("CWE-347").owaspCategory("A02:2021 - Cryptographic Failures")
                        .recommendation("Never accept the 'none' algorithm. Always require RS256 or HS256 with strong keys.")
                        .confidence("High")
                        .build());
                    break;
                }
            }

            return vulns;
        }
    }

    // ===== TIMING ATTACKS =====
    public static class TimingAttackRule implements ScanRule {
        @Override public String getRuleId() { return "JAVA-TIME-001"; }
        @Override public String getCategory() { return "Timing Attack"; }

        @Override
        public List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker) {
            List<VulnerabilityReport> vulns = new ArrayList<>();

            cu.findAll(MethodCallExpr.class).forEach(mce -> {
                if (mce.getNameAsString().equals("equals")) {
                    String context = mce.findAncestor(MethodDeclaration.class).map(m -> m.toString().toLowerCase()).orElse("");
                    boolean securityContext = context.contains("token") || context.contains("password") ||
                        context.contains("secret") || context.contains("key") || context.contains("hash") ||
                        context.contains("hmac") || context.contains("signature") || context.contains("apikey") ||
                        context.contains("api_key") || context.contains("auth");

                    if (securityContext) {
                        mce.getScope().ifPresent(scope -> {
                            String scopeStr = scope.toString().toLowerCase();
                            if (scopeStr.contains("token") || scopeStr.contains("password") ||
                                scopeStr.contains("secret") || scopeStr.contains("key") ||
                                scopeStr.contains("hash") || scopeStr.contains("hmac") ||
                                scopeStr.contains("signature") || scopeStr.contains("apikey")) {
                                int line = mce.getBegin().map(p -> p.line).orElse(0);
                                vulns.add(VulnerabilityReport.builder()
                                    .category("Timing Attack")
                                    .severity("Medium")
                                    .title("Potential timing attack via String.equals() on secret comparison")
                                    .description("String.equals() performs early termination, leaking information about the secret through timing differences.")
                                    .filePath(filePath).lineNumber(line)
                                    .codeSnippet(SqlInjectionRule.getSnippet(sourceCode, line))
                                    .cweId("CWE-208").owaspCategory("A02:2021 - Cryptographic Failures")
                                    .recommendation("Use MessageDigest.isEqual() or a constant-time comparison function.")
                                    .confidence("Medium")
                                    .build());
                            }
                        });
                    }
                }
            });

            return vulns;
        }
    }
}
