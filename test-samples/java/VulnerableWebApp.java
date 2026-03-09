package com.example.vulnerable;

import javax.servlet.http.*;
import javax.servlet.*;
import java.io.*;
import java.sql.*;
import java.util.Random;
import java.security.MessageDigest;
import javax.crypto.Cipher;

/**
 * INTENTIONALLY VULNERABLE - Test file for SAST scanner validation.
 * DO NOT use in production.
 */
public class VulnerableWebApp extends HttpServlet {

    // VULN: Hardcoded database password
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY = "sk-abc123def456ghi789";
    private static final String JWT_SECRET = "myweaksecret";

    // ============ SQL INJECTION ============
    public void handleLogin(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", DB_PASSWORD);
            // VULN: SQL Injection via string concatenation
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                response.getWriter().println("Welcome " + username);
            }
        } catch (SQLException e) {
            // VULN: Stack trace in response
            e.printStackTrace(response.getWriter());
        }
    }

    // VULN: SQL Injection via String.format
    public void searchUsers(HttpServletRequest request) throws SQLException {
        String searchTerm = request.getParameter("search");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        Statement stmt = conn.createStatement();
        String query = String.format("SELECT * FROM users WHERE name LIKE '%%%s%%'", searchTerm);
        stmt.executeQuery(query);
    }

    // ============ COMMAND INJECTION ============
    public void runDiagnostic(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String hostname = request.getParameter("host");
        // VULN: Command injection via Runtime.exec
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("ping -c 3 " + hostname);

        // VULN: Command injection via ProcessBuilder
        ProcessBuilder pb = new ProcessBuilder("nslookup", hostname);
        pb.start();
    }

    // ============ XSS ============
    public void displayProfile(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        PrintWriter writer = response.getWriter();
        // VULN: Reflected XSS - writing user input directly to response
        writer.println("<h1>Welcome, " + name + "</h1>");

        String bio = request.getParameter("bio");
        // VULN: XSS via response getWriter
        response.getWriter().print("<div class='bio'>" + bio + "</div>");
    }

    // ============ PATH TRAVERSAL ============
    public void downloadFile(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String fileName = request.getParameter("file");
        // VULN: Path traversal via File constructor
        File file = new File("/var/uploads/" + fileName);
        FileInputStream fis = new FileInputStream(file);

        // VULN: Path traversal via FileReader
        String reportName = request.getParameter("report");
        FileReader reader = new FileReader("/var/reports/" + reportName);
    }

    // ============ DESERIALIZATION ============
    public void processData(HttpServletRequest request) throws Exception {
        // VULN: Insecure deserialization
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject();
        System.out.println("Received object: " + obj.toString());
    }

    // ============ XXE ============
    public void parseXmlInput(HttpServletRequest request) throws Exception {
        // VULN: XXE - DocumentBuilderFactory without secure configuration
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc = db.parse(request.getInputStream());
    }

    // ============ SSRF ============
    public void fetchExternalUrl(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String targetUrl = request.getParameter("url");
        // VULN: SSRF via URL with user input
        java.net.URL url = new java.net.URL(targetUrl);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = br.readLine()) != null) {
            response.getWriter().println(line);
        }
    }

    // ============ WEAK CRYPTOGRAPHY ============
    public String hashPassword(String password) throws Exception {
        // VULN: Weak hash algorithm MD5
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return new String(digest);
    }

    public byte[] encryptData(byte[] data) throws Exception {
        // VULN: Weak encryption - DES
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }

    public byte[] encryptWithEcb(byte[] data) throws Exception {
        // VULN: ECB mode
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }

    // ============ INSECURE RANDOM ============
    public String generateToken() {
        // VULN: Insecure random for security-sensitive token
        Random random = new Random();
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append((char) (random.nextInt(26) + 'a'));
        }
        return token.toString();
    }

    public String generateSessionId() {
        // VULN: Math.random for session ID
        return "SESSION_" + (long)(Math.random() * 1000000000L);
    }

    // ============ RESOURCE LEAK ============
    public String readConfig(String path) throws IOException {
        // VULN: Resource leak - FileInputStream not closed
        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[1024];
        fis.read(data);
        return new String(data);
    }

    public void queryDatabase() throws SQLException {
        // VULN: Resource leak - Connection and Statement not in try-with-resources
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT 1");
    }

    // ============ INFORMATION DISCLOSURE ============
    public void handleError(HttpServletRequest request, HttpServletResponse response) {
        try {
            // some operation
            int result = Integer.parseInt(request.getParameter("id"));
        } catch (Exception e) {
            // VULN: printStackTrace exposes internals
            e.printStackTrace();
        }
    }

    // ============ EMPTY CATCH BLOCK ============
    public void processPayment(String amount) {
        try {
            double val = Double.parseDouble(amount);
            // process payment
        } catch (NumberFormatException e) {
            // VULN: Empty catch block swallows exception
        }
    }

    // ============ INSECURE TLS ============
    public void connectToApi() throws Exception {
        // VULN: Deprecated TLS protocol
        javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, null);
    }

    // ============ SERVLET SECURITY ============
    public void handleLoginSession(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String user = request.getParameter("user");
        // VULN: Session fixation - no invalidate() before getSession
        HttpSession session = request.getSession();
        session.setAttribute("user", user);

        // VULN: Cookie without HttpOnly and Secure flags
        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("sessionToken", "abc123");
        response.addCookie(cookie);
    }
}
