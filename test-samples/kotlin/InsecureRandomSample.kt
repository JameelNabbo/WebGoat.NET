package com.example.vulnerable

import java.util.Random

class TokenGenerator {

    // VULN: java.util.Random for token generation
    fun generateToken(): String {
        val random = Random()
        val token = (1..32).map { random.nextInt(36).toString(36) }.joinToString("")
        return token
    }

    // VULN: Math.random() for OTP
    fun generateOtp(): String {
        val otp = (Math.random() * 1000000).toInt()
        return otp.toString().padStart(6, '0')
    }

    // SAFE: SecureRandom
    fun generateSecureToken(): String {
        val random = java.security.SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
