package main

import (
	"fmt"
	"net/http"
	"text/template"
)

// VULN: XSS - text/template used instead of html/template
func renderPage(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	tmpl := template.New("page")
	tmpl, _ = tmpl.Parse("<html><body>Hello {{.Name}}</body></html>")
	tmpl.Execute(w, map[string]string{"Name": name})
}

// VULN: XSS - user input written directly to response via Write
func echoInput(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("q")
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<h1>Search: " + userInput + "</h1>"))
}

// VULN: XSS - user input via fmt.Fprintf to response
func greetUser(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body>Welcome, %s!</body></html>", name)
}

// VULN: XSS - reflected via WriteString
func searchResults(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	w.Header().Set("Content-Type", "text/html")
	w.WriteString("<html><body>Results for: " + query + "</body></html>")
}
