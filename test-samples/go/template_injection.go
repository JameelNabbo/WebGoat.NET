package main

import (
	"net/http"
	"text/template"
)

// VULN: Template injection - user input used as template string
func renderUserTemplate(w http.ResponseWriter, r *http.Request) {
	userTemplate := r.FormValue("template")
	tmpl, err := template.New("user").Parse(userTemplate)
	if err != nil {
		http.Error(w, "Template error", 500)
		return
	}
	tmpl.Execute(w, map[string]string{"Name": "World"})
}

// VULN: Template injection - concatenated user input in template
func dynamicTemplate(w http.ResponseWriter, r *http.Request) {
	greeting := r.FormValue("greeting")
	tmplStr := "<html><body>" + greeting + " {{.Name}}</body></html>"
	tmpl := template.Must(template.New("page").Parse(tmplStr))
	tmpl.Execute(w, map[string]string{"Name": "User"})
}

// VULN: text/template with Execute to ResponseWriter (no auto-escaping)
func textTemplateRender(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("page").Parse("{{.Content}}"))
	content := r.FormValue("content")
	tmpl.Execute(w, map[string]string{"Content": content})
}
