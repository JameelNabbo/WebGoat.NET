package scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;

/**
 * Java SAST Scanner - HTTP service for static analysis of Java source code.
 *
 * Endpoints:
 *   GET  /health  - Health check
 *   POST /scan    - Scan Java files for vulnerabilities
 *
 * Port: 9004 (default, configurable via SCANNER_PORT env var)
 */
public class JavaSastScanner {
    private static final Logger logger = LoggerFactory.getLogger(JavaSastScanner.class);

    private static final String VERSION = "1.0.0";
    private static final int DEFAULT_PORT = 9004;

    private final ObjectMapper objectMapper;
    private final AstAnalyzer analyzer;
    private HttpServer server;

    public JavaSastScanner() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        this.analyzer = new AstAnalyzer();
    }

    public void start(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));

        // Health endpoint
        server.createContext("/health", new HealthHandler());

        // Scan endpoint
        server.createContext("/scan", new ScanHandler());

        // Root endpoint
        server.createContext("/", new RootHandler());

        server.start();
        logger.info("Java SAST Scanner v{} started on port {}", VERSION, port);
        logger.info("Loaded {} vulnerability detection rules across {} categories",
            analyzer.getRuleCount(), analyzer.getCategories().size());
        logger.info("Categories: {}", analyzer.getCategories());
        logger.info("Endpoints: GET /health, POST /scan");
    }

    // ===== HEALTH HANDLER =====
    class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
                return;
            }

            Map<String, Object> health = new LinkedHashMap<>();
            health.put("status", "healthy");
            health.put("scanner", "java-sast-scanner");
            health.put("version", VERSION);
            health.put("language", "java");
            health.put("rulesLoaded", analyzer.getRuleCount());
            health.put("categories", analyzer.getCategories());
            health.put("uptime", ManagementFactory_getUptime());

            String json = objectMapper.writeValueAsString(health);
            sendResponse(exchange, 200, json);
        }
    }

    // ===== SCAN HANDLER =====
    class ScanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed. Use POST.\"}");
                return;
            }

            try {
                // Read request body
                String requestBody;
                try (InputStream is = exchange.getRequestBody();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    requestBody = sb.toString();
                }

                if (requestBody.trim().isEmpty()) {
                    sendResponse(exchange, 400, "{\"error\": \"Empty request body\"}");
                    return;
                }

                // Parse request
                ScanRequest request;
                try {
                    request = objectMapper.readValue(requestBody, ScanRequest.class);
                } catch (Exception e) {
                    sendResponse(exchange, 400,
                        "{\"error\": \"Invalid JSON: " + escapeJson(e.getMessage()) + "\"}");
                    return;
                }

                if (request.getFiles() == null || request.getFiles().isEmpty()) {
                    sendResponse(exchange, 400, "{\"error\": \"No files provided. Expected: {\\\"files\\\": {\\\"path/File.java\\\": \\\"content\\\", ...}}\"}");
                    return;
                }

                String scanId = request.getScanId();
                if (scanId == null || scanId.isEmpty()) {
                    scanId = UUID.randomUUID().toString();
                }

                logger.info("Starting scan {} with {} files", scanId, request.getFiles().size());

                // Perform scan
                ScanResponse response = analyzer.scanFiles(request.getFiles(), scanId);

                // Send response
                String json = objectMapper.writeValueAsString(response);
                sendResponse(exchange, 200, json);

            } catch (Exception e) {
                logger.error("Scan failed", e);
                sendResponse(exchange, 500,
                    "{\"error\": \"Internal server error: " + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    // ===== ROOT HANDLER =====
    class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", "Java SAST Scanner");
            info.put("version", VERSION);
            info.put("description", "Comprehensive static analysis security scanner for Java source code");
            info.put("endpoints", Arrays.asList(
                Map.of("method", "GET", "path", "/health", "description", "Health check"),
                Map.of("method", "POST", "path", "/scan", "description", "Scan Java files for vulnerabilities")
            ));
            info.put("vulnerabilityCategories", analyzer.getCategories());
            info.put("totalRules", analyzer.getRuleCount());

            String json = objectMapper.writeValueAsString(info);
            sendResponse(exchange, 200, json);
        }
    }

    // ===== UTILITY METHODS =====
    private void sendResponse(HttpExchange exchange, int statusCode, String body) throws IOException {
        byte[] responseBytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "null";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private long ManagementFactory_getUptime() {
        try {
            return java.lang.management.ManagementFactory.getRuntimeMXBean().getUptime();
        } catch (Exception e) {
            return -1;
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(2);
        }
        analyzer.shutdown();
    }

    // ===== MAIN =====
    public static void main(String[] args) {
        int port = DEFAULT_PORT;

        // Check for port argument
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                logger.warn("Invalid port argument: {}. Using default: {}", args[0], DEFAULT_PORT);
            }
        }

        // Check for environment variable
        String envPort = System.getenv("SCANNER_PORT");
        if (envPort != null) {
            try {
                port = Integer.parseInt(envPort);
            } catch (NumberFormatException e) {
                logger.warn("Invalid SCANNER_PORT env var: {}. Using default: {}", envPort, DEFAULT_PORT);
            }
        }

        JavaSastScanner scanner = new JavaSastScanner();
        try {
            scanner.start(port);

            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Shutting down Java SAST Scanner...");
                scanner.stop();
            }));

            // Keep running
            System.out.println("Java SAST Scanner v" + VERSION + " running on port " + port);
            System.out.println("Press Ctrl+C to stop");

            // Block main thread
            Thread.currentThread().join();

        } catch (Exception e) {
            logger.error("Failed to start scanner", e);
            System.err.println("Failed to start scanner: " + e.getMessage());
            System.exit(1);
        }
    }
}
