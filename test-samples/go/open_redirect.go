package main

import (
	"net/http"
)

// VULN: Open Redirect - user-controlled redirect URL
func loginRedirect(w http.ResponseWriter, r *http.Request) {
	returnURL := r.FormValue("return_url")
	http.Redirect(w, r, returnURL, http.StatusFound)
}

// VULN: Open Redirect via header manipulation
func headerRedirect(w http.ResponseWriter, r *http.Request) {
	nextPage := r.FormValue("next")
	w.Header().Set("Location", nextPage)
	w.WriteHeader(http.StatusMovedPermanently)
}

// VULN: Open Redirect - URL from query parameter
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear session...
	redirectTo := r.URL.Query().Get("redirect")
	http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
}
