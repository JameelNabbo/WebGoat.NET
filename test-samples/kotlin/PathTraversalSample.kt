package com.example.vulnerable

import java.io.File
import java.io.FileInputStream

class FileService {

    // VULN: File path from user input without validation
    fun downloadFile(fileName: String): ByteArray {
        val file = File("/uploads/$fileName")
        return FileInputStream(file).readBytes()
    }

    // VULN: Path from user input in FileReader
    fun readConfig(configPath: String): String {
        val reader = java.io.FileReader(configPath)
        return reader.readText()
    }

    // SAFE: Uses canonical path validation
    fun safeDownload(fileName: String): ByteArray {
        val baseDir = File("/uploads").canonicalPath
        val file = File("/uploads/$fileName")
        if (!file.canonicalPath.startsWith(baseDir)) {
            throw SecurityException("Path traversal attempt")
        }
        return file.readBytes()
    }
}
