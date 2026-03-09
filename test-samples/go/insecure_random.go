package main

import (
	"fmt"
	"math/rand"
	"net/http"
)

// VULN: math/rand used for session token generation (predictable)
func generateSessionToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, 32)
	for i := range token {
		token[i] = charset[rand.Intn(len(charset))]
	}
	return string(token)
}

// VULN: math/rand used for password reset token
func generateResetToken() string {
	return fmt.Sprintf("%d", rand.Int63())
}

// VULN: math/rand used for OTP generation
func generateOTP() string {
	otp := rand.Intn(999999)
	return fmt.Sprintf("%06d", otp)
}

// VULN: math/rand for CSRF token
func csrfHandler(w http.ResponseWriter, r *http.Request) {
	csrf := fmt.Sprintf("%x", rand.Int63())
	http.SetCookie(w, &http.Cookie{
		Name:  "csrf_token",
		Value: csrf,
	})
	w.Write([]byte("Token set"))
}
