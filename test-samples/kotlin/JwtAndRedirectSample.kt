package com.example.vulnerable

import io.ktor.server.application.*
import io.ktor.server.response.*

class AuthService {

    // VULN: JWT with none algorithm
    fun createToken(userId: String): String {
        val algorithm = "none"
        val header = """{"alg":"$algorithm","typ":"JWT"}"""
        val payload = """{"sub":"$userId"}"""
        return "$header.$payload."
    }

    // VULN: Hardcoded JWT secret
    val jwtSigningKey = "my-super-secret-jwt-key-never-share-this"

    // VULN: Open redirect
    suspend fun handleRedirect(call: ApplicationCall) {
        val returnUrl = call.parameters["returnUrl"] ?: "/"
        call.respondRedirect(returnUrl)
    }

    // VULN: Open redirect with sendRedirect
    fun legacyRedirect(response: Any, url: String) {
        (response as javax.servlet.http.HttpServletResponse).sendRedirect(url)
    }
}
