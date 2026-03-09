package com.example.vulnerable

import kotlinx.coroutines.*

class CounterService {

    // VULN: Mutable shared state accessed in coroutines
    var requestCount = 0
    var lastError: String? = null

    // VULN: GlobalScope usage
    fun processAsync(data: String) {
        GlobalScope.launch {
            requestCount++
            try {
                heavyComputation(data)
            } catch (e: Exception) {
                lastError = e.message
            }
        }
    }

    // VULN: Shared mutable state in launch blocks
    fun processBatch(items: List<String>) {
        val scope = CoroutineScope(Dispatchers.Default)
        items.forEach { item ->
            scope.launch {
                requestCount++
                process(item)
            }
        }
    }

    // SAFE: Using Mutex
    val safeMutex = kotlinx.coroutines.sync.Mutex()
    var safeCounter = 0

    suspend fun safeIncrement() {
        safeMutex.withLock {
            safeCounter++
        }
    }

    private suspend fun heavyComputation(data: String) { delay(1000) }
    private fun process(item: String) { /* ... */ }
}
