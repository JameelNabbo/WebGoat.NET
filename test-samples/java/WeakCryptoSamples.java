package com.test.vulnerable;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * Weak Cryptography Test Samples
 * Tests: DES, MD5, SHA1, ECB mode, insecure random
 */
public class WeakCryptoSamples {

    // 1. DES - weak block cipher
    public byte[] encryptDES(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // 2. MD5 - weak hash
    public byte[] hashMD5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    // 3. SHA-1 - weak hash
    public byte[] hashSHA1(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    // 4. AES ECB mode - pattern leaking
    public byte[] encryptECB(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // 5. RC4 - broken stream cipher
    public byte[] encryptRC4(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        SecretKeySpec keySpec = new SecretKeySpec(key, "RC4");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // 6. Insecure Random
    public int generateToken() {
        java.util.Random random = new java.util.Random();
        return random.nextInt(999999);
    }

    // 7. Math.random for security-sensitive operation
    public String generateSessionId() {
        long value = (long)(Math.random() * Long.MAX_VALUE);
        return Long.toHexString(value);
    }

    // 8. SAFE - SecureRandom (should NOT flag as insecure random)
    public byte[] secureRandomBytes() {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[32];
        sr.nextBytes(bytes);
        return bytes;
    }
}
