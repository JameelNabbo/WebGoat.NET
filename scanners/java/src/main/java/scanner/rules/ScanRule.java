package scanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import scanner.TaintTracker;
import scanner.VulnerabilityReport;

import java.util.List;

/**
 * Interface for all vulnerability detection rules.
 */
public interface ScanRule {
    /**
     * Get the rule identifier.
     */
    String getRuleId();

    /**
     * Get the vulnerability category.
     */
    String getCategory();

    /**
     * Scan a compilation unit for vulnerabilities.
     * @param cu The parsed compilation unit
     * @param filePath The file path being scanned
     * @param sourceCode The raw source code
     * @param taintTracker The taint tracker for data flow analysis
     * @return List of found vulnerabilities
     */
    List<VulnerabilityReport> scan(CompilationUnit cu, String filePath, String sourceCode, TaintTracker taintTracker);
}
