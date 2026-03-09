package com.example.ktor

import io.ktor.application.*
import io.ktor.features.*
import io.ktor.http.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import kotlinx.coroutines.*
import java.io.File
import java.net.URL

// =============================================================================
// 18. Ktor Security Issues
// =============================================================================
fun Application.module() {
    // VULN: CORS anyHost
    install(CORS) {
        anyHost()
        allowHeader(HttpHeaders.ContentType)
        allowCredentials = true
    }

    routing {
        // VULN: Route without authentication
        route("/api/admin") {
            get("/users") {
                val users = getAllUsers()
                call.respondText(users.toString(), ContentType.Text.Html)
            }

            post("/execute") {
                val body = call.receiveText()
                // VULN: SSRF from user URL
                val url = URL("$body")
                val result = url.readText()
                // VULN: XSS - respondText as HTML with user data
                call.respondText("<div>$result</div>", ContentType.Text.Html)
            }

            get("/file") {
                val fileName = call.request.queryParameters["name"] ?: ""
                // VULN: Path traversal
                val file = File("/data/$fileName")
                call.respondText(file.readText())
            }

            get("/redirect") {
                val target = call.request.queryParameters["url"] ?: "/"
                // VULN: Open redirect
                call.respondRedirect("$target")
            }

            get("/error") {
                try {
                    throw RuntimeException("test")
                } catch (e: Exception) {
                    // VULN: Stack trace in response
                    call.respondText(e.stackTrace.joinToString("\n"))
                }
            }
        }

        // VULN: Debug endpoint
        get("/debug/dump") {
            call.respondText("debug info here")
        }
    }
}

private fun getAllUsers(): List<String> = listOf("admin", "user1")

// =============================================================================
// 19. Spring Boot Kotlin Issues
// =============================================================================
// Simulated Spring annotations
annotation class RestController
annotation class GetMapping(val value: String = "")
annotation class PostMapping(val value: String = "")
annotation class RequestBody
annotation class CrossOrigin(val origins: String = "")
annotation class Value(val value: String = "")

@RestController
@CrossOrigin(origins = "*")
class AdminController {

    // VULN: SpEL injection
    @Value("#{systemProperties['user.input']}")
    lateinit var userConfig: String

    @PostMapping("/api/process")
    fun processInput(@RequestBody input: UserInput) {
        // VULN: @RequestBody mass assignment
        val parser = org.springframework.expression.spel.standard.SpelExpressionParser()
        // VULN: Dynamic SpEL with user input
        val expression = parser.parseExpression("${input.expression}")
    }
}

data class UserInput(
    val expression: String,
    val role: String,
    val isAdmin: Boolean
)

// =============================================================================
// Additional Ktor + Coroutine Issues
// =============================================================================
class BackgroundProcessor {
    var taskCount = 0
    val results = mutableMapOf<String, String>()

    suspend fun processAll(tasks: List<String>) {
        // VULN: GlobalScope
        GlobalScope.launch {
            tasks.forEach { task ->
                // VULN: Shared mutable state in coroutine
                taskCount++
                results[task] = processTask(task)
            }
        }

        // VULN: runBlocking in production
        runBlocking {
            delay(5000)
        }
    }

    private suspend fun processTask(task: String): String {
        delay(100)
        return task.uppercase()
    }
}

// =============================================================================
// 7. SSRF with various HTTP clients
// =============================================================================
class HttpService {
    fun fetchWithOkHttp(userUrl: String): String {
        // VULN: OkHttp with user URL
        val client = okhttp3.OkHttpClient()
        val request = okhttp3.Request.Builder()
            .url("$userUrl/api/data")
            .build()
        return client.newCall(request).execute().body?.string() ?: ""
    }

    fun fetchWithRetrofit(baseUrl: String) {
        // VULN: Retrofit baseUrl from user
        val retrofit = retrofit2.Retrofit.Builder()
            .baseUrl("$baseUrl")
            .build()
    }
}

// =============================================================================
// File Upload without validation
// =============================================================================
class UploadHandler {
    suspend fun handleUpload(call: ApplicationCall) {
        val multipart = call.receiveMultipart()
        // VULN: File upload without validation
        multipart.forEachPart { part ->
            if (part is io.ktor.http.content.PartData.FileItem) {
                val file = File("/uploads/${part.originalFileName}")
                part.streamProvider().use { input ->
                    file.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
            }
        }
    }
}
