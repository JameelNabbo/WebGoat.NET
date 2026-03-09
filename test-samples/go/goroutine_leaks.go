package main

import (
	"fmt"
	"net/http"
	"time"
)

// VULN: Goroutine leak - channel never read
func leakyGoroutine() {
	ch := make(chan int)
	go func() {
		result := heavyComputation()
		ch <- result // Blocks forever if nobody reads
	}()
	// ch is never read - goroutine leaks
}

func heavyComputation() int {
	time.Sleep(10 * time.Second)
	return 42
}

// VULN: Goroutine leak - unbounded goroutine spawning in HTTP handler
func handleRequestLeaky(w http.ResponseWriter, r *http.Request) {
	go func() {
		// Long-running background task spawned per request
		time.Sleep(30 * time.Second)
		fmt.Println("Background task done")
	}()
	w.Write([]byte("Request accepted"))
}

// VULN: Goroutine leak - select without timeout/context
func waitForever() {
	ch1 := make(chan string)
	ch2 := make(chan string)

	go func() {
		select {
		case msg := <-ch1:
			fmt.Println(msg)
		case msg := <-ch2:
			fmt.Println(msg)
		// Missing: case <-ctx.Done() or case <-time.After(...)
		}
	}()
}

// VULN: Goroutine leak - ticker not stopped
func pollForever() {
	ticker := time.NewTicker(1 * time.Second)
	// Missing: defer ticker.Stop()
	go func() {
		for range ticker.C {
			fmt.Println("tick")
		}
	}()
}
