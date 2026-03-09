package com.example.vulnerable

class AuthValidator {

    // VULN: Non-constant-time token comparison
    fun validateToken(providedToken: String, storedToken: String): Boolean {
        return providedToken == storedToken
    }

    // VULN: Non-constant-time password hash comparison
    fun verifyPassword(inputHash: String, storedHash: String): Boolean {
        return inputHash == storedHash
    }

    // VULN: Non-constant-time CSRF token check
    fun validateCsrf(requestCsrf: String, sessionCsrf: String): Boolean {
        return requestCsrf == sessionCsrf
    }

    // SAFE: Constant-time comparison
    fun validateTokenSafe(providedToken: String, storedToken: String): Boolean {
        return java.security.MessageDigest.isEqual(
            providedToken.toByteArray(),
            storedToken.toByteArray()
        )
    }
}
