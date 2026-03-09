package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// VULN: Hardcoded password in variable assignment
var dbPassword = "SuperSecretP@ss123"

// VULN: Hardcoded API key in constant
const (
	APIKey       = "sk-live-4eC39HqLyjWDarjtT1zdp7dc"
	SecretToken  = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_1234"
	DatabasePassword = "p@ssw0rd!2026"
)

// VULN: Hardcoded AWS credentials
var awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
var awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

// VULN: Hardcoded connection string
var connectionString = "mongodb://admin:secretpass@localhost:27017/mydb"

// VULN: Hardcoded JWT secret
var jwtSecret = "my-super-secret-jwt-signing-key-2026"

// VULN: Hardcoded authorization header
func callAPI() {
	authorization := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	fmt.Println(authorization)
}

// VULN: Private key embedded in code
var privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA6744bPMkRfSw
-----END RSA PRIVATE KEY-----`

func connectDB() (*sql.DB, error) {
	// VULN: Hardcoded database URL
	databaseUrl := "postgres://admin:hunter2@db.example.com:5432/production"
	return sql.Open("postgres", databaseUrl)
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello")
}
