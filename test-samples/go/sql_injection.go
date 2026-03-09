package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// VULN: SQL Injection via string concatenation in Query
func getUserByName(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Error", 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Results: %v", rows)
}

// VULN: SQL Injection via fmt.Sprintf in Exec
func deleteUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("id")
	query := fmt.Sprintf("DELETE FROM users WHERE id = %s", userID)
	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, "Error", 500)
	}
}

// VULN: SQL Injection via tainted variable propagation in QueryRow
func getProfile(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	searchTerm := "%" + email + "%"
	q := "SELECT name, bio FROM profiles WHERE email LIKE '" + searchTerm + "'"
	var name, bio string
	db.QueryRow(q).Scan(&name, &bio)
	fmt.Fprintf(w, "Name: %s, Bio: %s", name, bio)
}

// SAFE: Parameterized query - should NOT trigger
func getUserSafe(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	rows, err := db.Query("SELECT * FROM users WHERE username = $1", username)
	if err != nil {
		http.Error(w, "Error", 500)
		return
	}
	defer rows.Close()
}

// VULN: SQL Injection in QueryContext
func searchProducts(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("search")
	query := "SELECT * FROM products WHERE name LIKE '" + term + "%'"
	rows, err := db.QueryContext(r.Context(), query)
	if err != nil {
		http.Error(w, "Error", 500)
		return
	}
	defer rows.Close()
}
