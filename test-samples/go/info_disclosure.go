package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime"
	"runtime/debug"
)

// VULN: Information disclosure - stack trace in error response
func debugHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			stack := debug.Stack()
			http.Error(w, fmt.Sprintf("Internal Error: %v\nStack: %s", err, stack), 500)
		}
	}()
	panic("something went wrong")
}

// VULN: Information disclosure - version info exposed
func statusHandler(w http.ResponseWriter, r *http.Request) {
	info := fmt.Sprintf("Go Version: %s\nOS: %s\nArch: %s\nGoroutines: %d",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumGoroutine())
	w.Write([]byte(info))
}

// VULN: Logging sensitive data
func logSensitiveData(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	email := r.FormValue("email")
	log.Printf("Login attempt: email=%s, password=%s", email, password)
	w.Write([]byte("Logged"))
}

// VULN: pprof exposed (typically imported as side-effect)
// import _ "net/http/pprof"
func exposeDebugEndpoints() {
	// Exposes /debug/pprof/ endpoints
	http.ListenAndServe(":6060", nil)
}
