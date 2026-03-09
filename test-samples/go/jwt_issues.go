package main

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// VULN: JWT - Hardcoded signing key
var jwtSigningKey = []byte("my-hardcoded-secret-key-1234567890")

// VULN: JWT - None algorithm accepted
func parseTokenInsecure(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Missing algorithm check - none algorithm attack possible
		return jwtSigningKey, nil
	})
	return token, err
}

// VULN: JWT - Algorithm not validated
func validateToken(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Should check: if _, ok := token.Method.(*jwt.SigningMethodHMAC); \!ok {
		return jwtSigningKey, nil
	})
	if err \!= nil || \!token.Valid {
		http.Error(w, "Unauthorized", 401)
		return
	}
	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "Welcome %s", claims["user"])
}

// VULN: JWT token in URL parameter (leaks in logs/referrer)
func tokenInURL(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	token, _ := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtSigningKey, nil
	})
	if token \!= nil && token.Valid {
		w.Write([]byte("Authenticated"))
	}
}
