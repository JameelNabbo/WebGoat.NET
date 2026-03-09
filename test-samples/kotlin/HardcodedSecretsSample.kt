package com.example.vulnerable

class AppConfig {

    // VULN: Hardcoded password
    val databasePassword = "SuperS3cretP@ssw0rd!"

    // VULN: Hardcoded API key
    val apiKey = "sk-1234567890abcdef1234567890abcdef"

    // VULN: Hardcoded JWT secret
    val jwtSecret = "my-super-secret-jwt-signing-key-2024"

    // VULN: Hardcoded token
    val accessToken = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_1234"

    // VULN: Hardcoded AWS key pattern
    val awsKey = "AKIAIOSFODNN7EXAMPLE"

    // VULN: Constant credential
    companion object {
        const val DB_PASSWORD = "admin123!@#"
        const val API_SECRET = "xoxb-FAKE-TEST-TOKEN"
        const val ENCRYPTION_KEY = "AES256-secret-key-do-not-share"
    }

    // SAFE: Environment variable
    val safePassword = System.getenv("DB_PASSWORD")

    // SAFE: Placeholder
    val placeholder = "CHANGE_ME"
}
