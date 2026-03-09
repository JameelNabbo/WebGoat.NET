package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// VULN: Error ignored - database error silently swallowed
func insertRecord(db *sql.DB, name string) {
	db.Exec("INSERT INTO records (name) VALUES ($1)", name)
	// Error from Exec is ignored
}

// VULN: Error ignored - file operation error silently dropped
func writeLog(message string) {
	f, _ := os.OpenFile("/var/log/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(message + "\n")
	f.Close()
}

// VULN: Sensitive error details exposed to user
func loginHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var req struct{ User, Pass string }
	json.NewDecoder(r.Body).Decode(&req)
	var hash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = $1", req.User).Scan(&hash)
	if err \!= nil {
		// Leaks DB error details including table/column names
		http.Error(w, fmt.Sprintf("Database error: %v", err), 500)
		return
	}
	w.Write([]byte("OK"))
}

// VULN: Panic used for error handling in HTTP handler
func panicHandler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	if data == "" {
		panic("no data provided") // Will crash the server
	}
	w.Write([]byte(data))
}
