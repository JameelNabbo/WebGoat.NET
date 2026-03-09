package com.test.vulnerable;

import java.sql.*;

/**
 * Hardcoded Secrets Test Samples
 * Tests: Passwords, API keys, connection strings in code
 */
public class HardcodedSecretsSamples {

    // 1. Hardcoded database password
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";

    // 2. Hardcoded API key
    private static final String API_KEY = "sk-1234567890abcdef1234567890abcdef";
    private static final String apiSecret = "a1b2c3d4e5f6g7h8i9j0";

    // 3. Hardcoded JWT secret
    private static final String JWT_SECRET = "myJwtSecretKeyForTokenSigning2024";
    private static final String jwtSigningKey = "HS256SigningKeyThatShouldBeExternalized";

    // 4. Hardcoded credentials in method
    public Connection getConnection() throws SQLException {
        String password = "admin123";
        return DriverManager.getConnection(DB_URL, "admin", password);
    }

    // 5. Hardcoded encryption key
    private static final String ENCRYPTION_KEY = "AES256EncryptionKeyHere!";
    private byte[] privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEF".getBytes();

    // 6. Connection string with embedded credentials
    private static final String CONNECTION_STRING = "mongodb://admin:password123@localhost:27017/mydb";

    // 7. Auth token
    private static final String AUTH_TOKEN = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_1234";
}
