package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// VULN: Path Traversal - user input in os.Open
func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	f, err := os.Open(filename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

// VULN: Path Traversal - user input in os.ReadFile
func readConfig(w http.ResponseWriter, r *http.Request) {
	configPath := r.FormValue("config")
	data, err := os.ReadFile(configPath)
	if err != nil {
		http.Error(w, "Error reading file", 500)
		return
	}
	w.Write(data)
}

// VULN: Path Traversal - tainted through filepath.Join
func downloadFile(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	fullPath := filepath.Join("/var/uploads", name)
	http.ServeFile(w, r, fullPath)
}

// VULN: Path Traversal - user input in os.Remove
func deleteFile(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	err := os.Remove(path)
	if err != nil {
		http.Error(w, "Delete failed", 500)
		return
	}
	w.Write([]byte("Deleted"))
}

// VULN: Path Traversal - os.Create with user input
func uploadFile(w http.ResponseWriter, r *http.Request) {
	destPath := r.FormValue("dest")
	f, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Create failed", 500)
		return
	}
	defer f.Close()
	io.Copy(f, r.Body)
}
