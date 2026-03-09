package scanner;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public class ScanRequest {
    @JsonProperty("files")
    private Map<String, String> files;

    @JsonProperty("scanId")
    private String scanId;

    public Map<String, String> getFiles() { return files; }
    public void setFiles(Map<String, String> files) { this.files = files; }
    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }
}
