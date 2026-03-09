package scanner;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class ScanResponse {
    @JsonProperty("scanId")
    private String scanId;

    @JsonProperty("status")
    private String status;

    @JsonProperty("totalFiles")
    private int totalFiles;

    @JsonProperty("filesScanned")
    private int filesScanned;

    @JsonProperty("totalVulnerabilities")
    private int totalVulnerabilities;

    @JsonProperty("vulnerabilities")
    private List<VulnerabilityReport> vulnerabilities;

    @JsonProperty("scanDurationMs")
    private long scanDurationMs;

    @JsonProperty("errors")
    private List<String> errors;

    public ScanResponse() {}

    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public int getTotalFiles() { return totalFiles; }
    public void setTotalFiles(int totalFiles) { this.totalFiles = totalFiles; }
    public int getFilesScanned() { return filesScanned; }
    public void setFilesScanned(int filesScanned) { this.filesScanned = filesScanned; }
    public int getTotalVulnerabilities() { return totalVulnerabilities; }
    public void setTotalVulnerabilities(int totalVulnerabilities) { this.totalVulnerabilities = totalVulnerabilities; }
    public List<VulnerabilityReport> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<VulnerabilityReport> vulnerabilities) { this.vulnerabilities = vulnerabilities; }
    public long getScanDurationMs() { return scanDurationMs; }
    public void setScanDurationMs(long scanDurationMs) { this.scanDurationMs = scanDurationMs; }
    public List<String> getErrors() { return errors; }
    public void setErrors(List<String> errors) { this.errors = errors; }
}
