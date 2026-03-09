package com.example.vulnerable

import java.io.BufferedReader
import java.io.InputStreamReader

class SystemUtils {

    // VULN: Runtime.exec with user input
    fun pingHost(host: String): String {
        val process = Runtime.getRuntime().exec("ping -c 4 $host")
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        return reader.readText()
    }

    // VULN: ProcessBuilder with user-controlled arguments
    fun convertFile(inputFile: String, outputFormat: String): Int {
        val pb = ProcessBuilder("convert", inputFile, "-format", outputFormat)
        val process = pb.start()
        return process.waitFor()
    }

    // VULN: Runtime.exec with hardcoded command (lower severity)
    fun getSystemInfo(): String {
        val process = Runtime.getRuntime().exec("uname -a")
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }

    // SAFE: No command execution
    fun formatOutput(data: String): String {
        return data.trim().uppercase()
    }
}
