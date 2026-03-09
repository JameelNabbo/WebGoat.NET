package com.example.vulnerable

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.response.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.sessions.*

fun main() {
    embeddedServer(Netty, port = 8080) {
        // VULN: CORS anyHost
        install(CORS) {
            anyHost()
            allowHeader("Authorization")
        }

        // VULN: Sessions without CSRF protection
        install(Sessions) {
            cookie<UserSession>("SESSION")
        }

        routing {
            // VULN: Route without authentication
            get("/api/users") {
                call.respondText("user list")
            }

            // VULN: Admin route without auth
            post("/api/admin/delete") {
                val userId = call.parameters["id"]
                call.respondText("deleted $userId")
            }

            // Acceptable: Public endpoints
            get("/health") {
                call.respondText("OK")
            }
        }
    }.start(wait = true)
}

data class UserSession(val userId: String, val token: String)
