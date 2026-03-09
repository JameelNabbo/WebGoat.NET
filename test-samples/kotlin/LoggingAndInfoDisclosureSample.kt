package com.example.vulnerable

import android.util.Log
import io.ktor.server.application.*
import io.ktor.server.response.*

class ErrorHandler {

    // VULN: Logging sensitive data
    fun authenticateUser(username: String, password: String): Boolean {
        Log.d("Auth", "Login attempt: user=$username, password=$password")
        return checkCredentials(username, password)
    }

    // VULN: Logging tokens
    fun processRequest(token: String) {
        println("Processing request with token: $token")
    }

    // VULN: Stack trace exposure
    suspend fun handleError(call: ApplicationCall, e: Exception) {
        e.printStackTrace()
        call.respondText("Error: ${e.message}")
    }

    // VULN: Verbose error with exception details
    suspend fun handleException(call: ApplicationCall, e: Exception) {
        call.respondText("Error occurred: ${e.stackTrace}")
    }

    // VULN: Debug mode enabled
    val debugMode = true

    // VULN: Internal URL hardcoded
    val internalApi = "http://192.168.1.100:8080/internal/admin"
    val localhostUrl = "http://localhost:3000/debug"

    private fun checkCredentials(u: String, p: String) = true
}
