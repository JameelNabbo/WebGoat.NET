package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
)

// VULN: Timing attack - string comparison for token validation
func validateAPIToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-API-Token")
	expectedToken := "secret-api-token-12345"
	if token == expectedToken { // Vulnerable to timing attack
		w.Write([]byte("Authorized"))
	} else {
		http.Error(w, "Unauthorized", 401)
	}
}

// VULN: Timing attack - byte comparison for HMAC
func validateHMAC(w http.ResponseWriter, r *http.Request) {
	message := r.FormValue("message")
	signature := r.FormValue("sig")

	mac := hmac.New(sha256.New, []byte("secret-key"))
	mac.Write([]byte(message))
	expected := mac.Sum(nil)

	// Direct string comparison - timing attack!
	if string(expected) == signature {
		w.Write([]byte("Valid"))
	} else {
		http.Error(w, "Invalid signature", 401)
	}
}

// SAFE: Using hmac.Equal for constant-time comparison
func validateHMACSafe(w http.ResponseWriter, r *http.Request) {
	message := r.FormValue("message")
	signature := []byte(r.FormValue("sig"))

	mac := hmac.New(sha256.New, []byte("secret-key"))
	mac.Write([]byte(message))
	expected := mac.Sum(nil)

	if hmac.Equal(expected, signature) {
		w.Write([]byte("Valid"))
	} else {
		http.Error(w, "Invalid signature", 401)
	}
}
