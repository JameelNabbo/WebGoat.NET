package main

import (
	"fmt"
	"io"
	"net/http"
)

// VULN: SSRF - http.Get with user-controlled URL
func fetchURL(w http.ResponseWriter, r *http.Request) {
	targetURL := r.FormValue("url")
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, "Fetch failed", 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// VULN: SSRF - http.Post with tainted URL
func postToURL(w http.ResponseWriter, r *http.Request) {
	endpoint := r.FormValue("endpoint")
	resp, err := http.Post(endpoint, "application/json", r.Body)
	if err != nil {
		http.Error(w, "Post failed", 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// VULN: SSRF - http.NewRequest with string concat URL
func proxyRequest(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	path := r.FormValue("path")
	url := "http://" + host + "/" + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, "Error", 500)
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error", 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// VULN: SSRF - http.Get with fmt.Sprintf URL
func fetchAPI(w http.ResponseWriter, r *http.Request) {
	apiHost := r.FormValue("api_host")
	url := fmt.Sprintf("https://%s/api/data", apiHost)
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "Error", 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
