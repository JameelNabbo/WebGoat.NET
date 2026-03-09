package com.example.vulnerable

import java.security.MessageDigest
import javax.crypto.Cipher

class CryptoService {

    // VULN: MD5 hash
    fun hashPassword(password: String): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        return digest.digest(password.toByteArray())
    }

    // VULN: SHA-1 hash
    fun generateChecksum(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA1")
        return digest.digest(data)
    }

    // VULN: DES encryption
    fun encryptData(data: ByteArray, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("DES")
        return cipher.doFinal(data)
    }

    // VULN: ECB mode
    fun encryptEcb(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        return cipher.doFinal(data)
    }

    // SAFE: SHA-256
    fun hashSafe(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
}
