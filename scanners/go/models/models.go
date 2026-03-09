package models

// ScanRequest is the JSON body for POST /scan
type ScanRequest struct {
	Files  map[string]string `json:"files"`
	ScanID string            `json:"scanId"`
}

// Severity levels
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"
)

// Confidence levels
const (
	ConfidenceHigh   = "High"
	ConfidenceMedium = "Medium"
	ConfidenceLow    = "Low"
)

// Vulnerability represents a single finding
type Vulnerability struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Category    string   `json:"category"`
	CWE         string   `json:"cwe"`
	OWASP       string   `json:"owasp,omitempty"`
	FilePath    string   `json:"filePath"`
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     string   `json:"snippet"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

// ScanResult is the response from POST /scan
type ScanResult struct {
	ScanID          string          `json:"scanId"`
	Language        string          `json:"language"`
	TotalFiles      int             `json:"totalFiles"`
	FilesScanned    int             `json:"filesScanned"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Errors          []string        `json:"errors,omitempty"`
	Duration        string          `json:"duration"`
}

// HealthResponse is the response from GET /health
type HealthResponse struct {
	Status   string `json:"status"`
	Language string `json:"language"`
	Version  string `json:"version"`
	Port     int    `json:"port"`
}
