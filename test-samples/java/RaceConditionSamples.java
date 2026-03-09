package com.test.vulnerable;

import java.util.*;

/**
 * Race Condition Test Samples
 * Tests: Shared mutable state without synchronization,
 *        check-then-act patterns, lazy init
 */
public class RaceConditionSamples {

    // 1. Shared mutable counter without synchronization
    private int requestCount = 0;
    private Map<String, Object> cache = new HashMap<>();

    public void handleRequest() {
        requestCount++;  // Race condition: not atomic
    }

    // 2. Check-then-act on shared map
    public Object getOrCreate(String key) {
        if (!cache.containsKey(key)) {
            // Another thread could insert between check and put
            cache.put(key, createExpensiveObject(key));
        }
        return cache.get(key);
    }

    // 3. Lazy singleton initialization without synchronization
    private static RaceConditionSamples instance;

    public static RaceConditionSamples getInstance() {
        if (instance == null) {
            instance = new RaceConditionSamples();
        }
        return instance;
    }

    // 4. Non-atomic compound operations
    private List<String> activeUsers = new ArrayList<>();

    public void addUser(String user) {
        if (!activeUsers.contains(user)) {
            activeUsers.add(user);
        }
    }

    public void removeUser(String user) {
        if (activeUsers.contains(user)) {
            activeUsers.remove(user);
        }
    }

    // 5. TOCTOU (Time-of-check, time-of-use) file operations
    public void writeIfNotExists(java.io.File file, String data) throws Exception {
        if (!file.exists()) {
            // Race: file could be created between check and write
            java.io.FileWriter fw = new java.io.FileWriter(file);
            fw.write(data);
            fw.close();
        }
    }

    private Object createExpensiveObject(String key) {
        return new Object();
    }
}
