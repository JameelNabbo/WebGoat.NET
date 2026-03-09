package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// VULN: Command Injection - user input directly in exec.Command
func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	cmd := exec.Command("ping", "-c", "4", host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "Ping failed", 500)
		return
	}
	w.Write(output)
}

// VULN: Command Injection - shell command with string concat
func runCommand(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	cmd := exec.Command("sh", "-c", "cat " + filename)
	output, _ := cmd.Output()
	w.Write(output)
}

// VULN: Command Injection - tainted through fmt.Sprintf
func convertFile(w http.ResponseWriter, r *http.Request) {
	inputFile := r.FormValue("input")
	outputFile := r.FormValue("output")
	cmdStr := fmt.Sprintf("ffmpeg -i %s %s", inputFile, outputFile)
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Run()
	w.Write([]byte("Conversion started"))
}

// SAFE: Hardcoded command - should NOT trigger
func getVersion(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("go", "version")
	output, _ := cmd.Output()
	w.Write(output)
}
