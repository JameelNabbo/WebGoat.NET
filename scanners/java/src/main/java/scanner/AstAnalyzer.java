package scanner;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import scanner.rules.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main AST analyzer that orchestrates all vulnerability scanning rules.
 */
public class AstAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(AstAnalyzer.class);

    private final List<ScanRule> rules;
    private final JavaParser parser;
    private final ExecutorService executor;

    public AstAnalyzer() {
        // Configure parser for Java 11 with lenient parsing
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_11);
        this.parser = new JavaParser(config);

        // Initialize all rules
        this.rules = new ArrayList<>();

        // Injection rules
        rules.add(new SqlInjectionRule());
        rules.add(new CommandInjectionRule());
        rules.add(new CodeInjectionRule());
        rules.add(new XssRule());
        rules.add(new PathTraversalRule());
        rules.add(new LdapInjectionRule());
        rules.add(new LogInjectionRule());

        // Deserialization and XML
        rules.add(new DeserializationRule());
        rules.add(new XxeRule());

        // Network
        rules.add(new SsrfRule());

        // Crypto and security
        rules.add(new CryptoSecurityRules.HardcodedSecretsRule());
        rules.add(new CryptoSecurityRules.WeakCryptoRule());
        rules.add(new CryptoSecurityRules.InsecureRandomRule());
        rules.add(new CryptoSecurityRules.InsecureTlsRule());
        rules.add(new CryptoSecurityRules.JwtIssuesRule());
        rules.add(new CryptoSecurityRules.TimingAttackRule());

        // Spring-specific
        rules.add(new SpringSecurityRules.SpelInjectionRule());
        rules.add(new SpringSecurityRules.CorsMisconfigRule());
        rules.add(new SpringSecurityRules.CsrfDisabledRule());
        rules.add(new SpringSecurityRules.ActuatorExposureRule());
        rules.add(new SpringSecurityRules.MassAssignmentRule());
        rules.add(new SpringSecurityRules.OpenRedirectRule());

        // Resource and code quality
        rules.add(new ResourceAndCodeQualityRules.ResourceLeakRule());
        rules.add(new ResourceAndCodeQualityRules.NullPointerRule());
        rules.add(new ResourceAndCodeQualityRules.RaceConditionRule());
        rules.add(new ResourceAndCodeQualityRules.InfoDisclosureRule());
        rules.add(new ResourceAndCodeQualityRules.InputValidationRule());
        rules.add(new ResourceAndCodeQualityRules.FileUploadRule());

        // Framework-specific
        rules.add(new AndroidAndFrameworkRules.AndroidSecurityRule());
        rules.add(new AndroidAndFrameworkRules.StrutsOgnlRule());
        rules.add(new AndroidAndFrameworkRules.HibernateHqlRule());
        rules.add(new AndroidAndFrameworkRules.ServletSecurityRule());

        // Thread pool for parallel file scanning
        this.executor = Executors.newFixedThreadPool(
            Math.min(Runtime.getRuntime().availableProcessors(), 8)
        );
    }

    /**
     * Scan multiple files in parallel.
     */
    public ScanResponse scanFiles(Map<String, String> files, String scanId) {
        long startTime = System.currentTimeMillis();

        ScanResponse response = new ScanResponse();
        response.setScanId(scanId);
        response.setTotalFiles(files.size());

        List<VulnerabilityReport> allVulns = Collections.synchronizedList(new ArrayList<>());
        List<String> errors = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger scannedCount = new AtomicInteger(0);

        List<Future<?>> futures = new ArrayList<>();

        for (Map.Entry<String, String> entry : files.entrySet()) {
            String filePath = entry.getKey();
            String sourceCode = entry.getValue();

            // Only scan .java files
            if (!filePath.endsWith(".java")) {
                continue;
            }

            futures.add(executor.submit(() -> {
                try {
                    List<VulnerabilityReport> fileVulns = scanSingleFile(filePath, sourceCode);
                    allVulns.addAll(fileVulns);
                    scannedCount.incrementAndGet();
                    logger.info("Scanned {}: {} vulnerabilities found", filePath, fileVulns.size());
                } catch (Exception e) {
                    errors.add("Error scanning " + filePath + ": " + e.getMessage());
                    logger.error("Error scanning {}", filePath, e);
                    scannedCount.incrementAndGet();
                }
            }));
        }

        // Wait for all files to be scanned
        for (Future<?> future : futures) {
            try {
                future.get(60, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                errors.add("Timeout scanning file");
            } catch (Exception e) {
                errors.add("Error: " + e.getMessage());
            }
        }

        long duration = System.currentTimeMillis() - startTime;

        // Deduplicate vulnerabilities
        List<VulnerabilityReport> dedupedVulns = deduplicateVulnerabilities(allVulns);

        response.setFilesScanned(scannedCount.get());
        response.setVulnerabilities(dedupedVulns);
        response.setTotalVulnerabilities(dedupedVulns.size());
        response.setScanDurationMs(duration);
        response.setErrors(errors);
        response.setStatus("completed");

        logger.info("Scan {} completed: {} files, {} vulnerabilities, {}ms",
            scanId, scannedCount.get(), dedupedVulns.size(), duration);

        return response;
    }

    /**
     * Scan a single file with all rules.
     */
    public List<VulnerabilityReport> scanSingleFile(String filePath, String sourceCode) {
        List<VulnerabilityReport> vulns = new ArrayList<>();

        // Parse the file
        ParseResult<CompilationUnit> parseResult = parser.parse(sourceCode);

        if (!parseResult.isSuccessful() || !parseResult.getResult().isPresent()) {
            logger.warn("Failed to parse {}: {}", filePath,
                parseResult.getProblems().isEmpty() ? "unknown error" :
                    parseResult.getProblems().get(0).getMessage());
            // Try lenient parsing - some rules can still work with partial AST
            return vulns;
        }

        CompilationUnit cu = parseResult.getResult().get();
        TaintTracker taintTracker = new TaintTracker();

        // Run all rules
        for (ScanRule rule : rules) {
            try {
                List<VulnerabilityReport> ruleVulns = rule.scan(cu, filePath, sourceCode, taintTracker);
                vulns.addAll(ruleVulns);
            } catch (Exception e) {
                logger.warn("Rule {} failed on {}: {}", rule.getRuleId(), filePath, e.getMessage());
            }
        }

        return vulns;
    }

    /**
     * Deduplicate vulnerabilities based on file, line, and category.
     */
    private List<VulnerabilityReport> deduplicateVulnerabilities(List<VulnerabilityReport> vulns) {
        Set<String> seen = new HashSet<>();
        List<VulnerabilityReport> deduped = new ArrayList<>();

        for (VulnerabilityReport v : vulns) {
            String key = v.getFilePath() + ":" + v.getLineNumber() + ":" + v.getCategory();
            if (seen.add(key)) {
                deduped.add(v);
            }
        }

        return deduped;
    }

    /**
     * Shutdown the executor service.
     */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }

    /**
     * Get the number of registered rules.
     */
    public int getRuleCount() {
        return rules.size();
    }

    /**
     * Get all rule categories.
     */
    public Set<String> getCategories() {
        Set<String> categories = new LinkedHashSet<>();
        for (ScanRule rule : rules) {
            categories.add(rule.getCategory());
        }
        return categories;
    }
}
