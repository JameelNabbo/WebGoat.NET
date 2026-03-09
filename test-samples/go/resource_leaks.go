package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

// VULN: Resource leak - HTTP response body not closed
func fetchData(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	// Missing: defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// VULN: Resource leak - file not closed
func readEntireFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	// Missing: defer f.Close()
	data, err := io.ReadAll(f)
	return string(data), err
}

// VULN: Resource leak - HTTP response body not closed on error path
func fetchAndProcess(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status: %d", resp.StatusCode) // Body leak on error
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err
}

// VULN: Multiple response bodies not closed in loop
func fetchMultiple(urls []string) []string {
	var results []string
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		// Missing: defer resp.Body.Close() inside loop does not help
		body, _ := io.ReadAll(resp.Body)
		results = append(results, string(body))
	}
	return results
}
