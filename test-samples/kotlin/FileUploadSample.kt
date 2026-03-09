package com.example.vulnerable

import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.request.*

class UploadService {

    // VULN: File upload without content type or size validation
    suspend fun handleUpload(call: ApplicationCall) {
        val multipart = call.receiveMultipart()
        multipart.forEachPart { part ->
            if (part is PartData.FileItem) {
                val fileName = part.originalFileName ?: "unknown"
                val file = java.io.File("/uploads/$fileName")
                part.streamProvider().use { input ->
                    file.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
            }
            part.dispose()
        }
    }
}
