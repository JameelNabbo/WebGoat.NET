package com.example.vulnerable

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

class WebController {

    // VULN: HTML with string interpolation in response
    suspend fun userProfile(call: ApplicationCall) {
        val username = call.parameters["name"] ?: "Guest"
        call.respondText(
            "<html><body><h1>Welcome, $username</h1></body></html>",
            ContentType.Text.Html
        )
    }

    // VULN: HTML string template with user input
    fun buildPage(userInput: String): String {
        return "<div class='content'><p>$userInput</p></div>"
    }

    // VULN: innerHTML manipulation
    fun setContent(element: Any, data: String) {
        element.innerHTML(data)
    }

    // SAFE: No HTML in response
    suspend fun apiEndpoint(call: ApplicationCall) {
        call.respondText("Hello, World!", ContentType.Text.Plain)
    }
}
