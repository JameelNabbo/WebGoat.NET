package com.example.vulnerable

import java.net.URL
import java.net.HttpURLConnection
import io.ktor.server.application.*

class ApiProxy {

    // VULN: SSRF via URL with user input
    fun fetchUrl(userUrl: String): String {
        val url = URL(userUrl)
        val connection = url.openConnection() as HttpURLConnection
        return connection.inputStream.bufferedReader().readText()
    }

    // VULN: SSRF via Ktor client with user-controlled URL
    suspend fun proxyRequest(call: ApplicationCall) {
        val targetUrl = call.parameters["url"] ?: return
        val response = client.get(targetUrl)
    }

    // VULN: OkHttp with variable URL
    fun fetchData(endpoint: String): String {
        val client = OkHttpClient()
        val request = Request.Builder().url(endpoint).build()
        return client.newCall(request).execute().body?.string() ?: ""
    }

    // SAFE: Hardcoded URL
    fun fetchKnownApi(): String {
        val url = URL("https://api.example.com/data")
        return url.openConnection().getInputStream().bufferedReader().readText()
    }
}
