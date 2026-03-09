package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gosastscanner/analyzer"
	"gosastscanner/models"
)

const (
	version = "1.0.0"
	port    = 9005
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/scan", scanHandler)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Go SAST Scanner v%s starting on port %d", version, port)
	log.Printf("Endpoints: GET /health, POST /scan")

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
		os.Exit(1)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := models.HealthResponse{
		Status:   "healthy",
		Language: "go",
		Version:  version,
		Port:     port,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()

	var req models.ScanRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(req.Files) == 0 {
		http.Error(w, "No files provided", http.StatusBadRequest)
		return
	}

	log.Printf("[%s] Starting scan: %d files", req.ScanID, len(req.Files))

	// Create analyzer and parse files
	a := analyzer.New()
	parseErrors := a.ParseFiles(req.Files)

	// Count Go files
	totalFiles := len(req.Files)
	goFiles := 0
	for path := range req.Files {
		if len(path) > 3 && path[len(path)-3:] == ".go" {
			goFiles++
		}
	}

	// Run analysis
	vulns := a.Analyze()

	duration := time.Since(start)

	result := models.ScanResult{
		ScanID:          req.ScanID,
		Language:        "go",
		TotalFiles:      totalFiles,
		FilesScanned:    goFiles,
		Vulnerabilities: vulns,
		Errors:          parseErrors,
		Duration:        duration.String(),
	}

	if result.Vulnerabilities == nil {
		result.Vulnerabilities = []models.Vulnerability{}
	}
	if result.Errors == nil {
		result.Errors = []string{}
	}

	log.Printf("[%s] Scan complete: %d files, %d vulnerabilities found in %s",
		req.ScanID, goFiles, len(vulns), duration)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
