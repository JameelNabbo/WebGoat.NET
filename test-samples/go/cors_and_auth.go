package main

import (
	"net/http"
)

// VULN: CORS misconfiguration - wildcard origin with credentials
func corsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	if r.Method == "OPTIONS" {
		w.WriteHeader(200)
		return
	}
	w.Write([]byte("API response"))
}

// VULN: CORS - reflecting Origin header without validation
func reflectOrigin(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Write([]byte("Response"))
}

// VULN: Missing authentication on sensitive endpoint
func adminHandler(w http.ResponseWriter, r *http.Request) {
	// No authentication check
	w.Write([]byte("Admin panel data"))
}

// VULN: Missing authentication on API endpoint
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// No auth check before destructive operation
	userID := r.FormValue("id")
	// db.Exec("DELETE FROM users WHERE id = $1", userID)
	w.Write([]byte("User " + userID + " deleted"))
}

func main() {
	http.HandleFunc("/api/data", corsHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/api/delete-user", deleteUserHandler)
	http.ListenAndServe(":8080", nil)
}
