package main

import (
	"fmt"
	"net/http"
	"sync"
)

// VULN: Race condition - shared counter without mutex
var requestCount int

func handleRequest(w http.ResponseWriter, r *http.Request) {
	requestCount++ // DATA RACE: concurrent read/write
	fmt.Fprintf(w, "Request #%d", requestCount)
}

// VULN: Race condition - shared map without synchronization
var userSessions = make(map[string]string)

func setSession(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	token := r.FormValue("token")
	userSessions[user] = token // DATA RACE: concurrent map write
	w.Write([]byte("Session set"))
}

// VULN: Race condition - goroutine accessing shared slice
var results []string

func processItems(items []string) {
	for _, item := range items {
		go func(s string) {
			results = append(results, s) // DATA RACE: concurrent append
		}(item)
	}
}

// VULN: Race condition - goroutine modifying shared variable
var balance float64 = 1000.0

func withdraw(amount float64) {
	go func() {
		if balance >= amount { // TOCTOU race
			balance -= amount // DATA RACE
		}
	}()
}

// SAFE: Properly synchronized with mutex - should show as safe pattern
var safeCounter int
var mu sync.Mutex

func safeIncrement() {
	mu.Lock()
	defer mu.Unlock()
	safeCounter++
}
