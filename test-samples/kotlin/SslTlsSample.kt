package com.example.vulnerable

import javax.net.ssl.*

class NetworkConfig {

    // VULN: HostnameVerifier that always returns true
    val unsafeVerifier = object : HostnameVerifier {
        override fun verify(hostname: String?, session: SSLSession?): Boolean {
            return true
        }
    }

    // VULN: HostnameVerifier bypass as property
    val hostnameVerifier: HostnameVerifier = HostnameVerifier { _, _ -> true }

    // VULN: SSLContext with trust-all manager
    fun createUnsafeSSLContext(): SSLContext {
        val trustAllCerts = arrayOf<TrustManager>(TrustAllManager())
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
        return sslContext
    }

    // VULN: Deprecated TLS version
    fun createOldTLS(): SSLContext {
        return SSLContext.getInstance("TLSv1")
    }

    // VULN: SSLv3
    fun createSSLv3(): SSLContext {
        return SSLContext.getInstance("SSLv3")
    }

    // SAFE: TLS 1.3
    fun createModernTLS(): SSLContext {
        return SSLContext.getInstance("TLSv1.3")
    }
}

class TrustAllManager : X509TrustManager {
    override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
}
