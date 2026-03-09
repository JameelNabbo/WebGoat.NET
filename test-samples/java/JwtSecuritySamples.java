package com.test.vulnerable;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

/**
 * JWT Security Test Samples
 * Tests: None algorithm, weak key, hardcoded JWT secret
 */
public class JwtSecuritySamples {

    // 1. Hardcoded JWT signing key
    private static final String JWT_SECRET = "mySecretJwtKey123";
    private static final String SIGNING_KEY = "shortkey";

    // 2. JWT verification with none algorithm accepted
    public boolean verifyToken(String token) {
        String[] parts = token.split("\\.");
        String header = new String(Base64.getDecoder().decode(parts[0]));
        // BUG: accepts "none" algorithm
        if (header.contains("\"alg\":\"none\"")) {
            return true;
        }
        // verify signature...
        return false;
    }

    // 3. Weak HMAC key for JWT
    public byte[] signJwt(String payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        // Weak key - should be at least 256 bits for HS256
        SecretKeySpec keySpec = new SecretKeySpec("weak".getBytes(), "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(payload.getBytes());
    }

    // 4. JWT secret in environment comparison
    public boolean validateSecret(String input) {
        String secret = "SuperSecretJWTKey2024!";
        return input.equals(secret);
    }

    // 5. Timing-vulnerable comparison
    public boolean timingVulnerableCompare(String provided, String expected) {
        return provided.equals(expected);
    }
}
