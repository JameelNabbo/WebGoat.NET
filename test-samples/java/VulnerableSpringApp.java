package com.example.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.*;
import javax.naming.*;
import java.io.*;
import java.util.*;

/**
 * INTENTIONALLY VULNERABLE Spring application - Test file for SAST scanner.
 */
@RestController
@CrossOrigin
public class VulnerableSpringApp {

    private static final String password = "Spring!Boot@2024";

    // Mutable shared state in singleton
    private int requestCount = 0;
    private Map<String, Object> cache = new HashMap<>();

    // ============ SpEL INJECTION ============
    @PostMapping("/evaluate")
    public String evaluateExpression(@RequestParam String expression) {
        // VULN: SpEL injection - user input passed to expression parser
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        Object result = parser.parseExpression(expression).getValue(context);
        return result.toString();
    }

    // ============ JNDI INJECTION ============
    @GetMapping("/lookup")
    public String jndiLookup(@RequestParam String name) throws NamingException {
        // VULN: JNDI injection
        InitialContext ctx = new InitialContext();
        Object obj = ctx.lookup(name);
        return obj.toString();
    }

    // ============ OPEN REDIRECT ============
    @GetMapping("/redirect")
    public void handleRedirect(@RequestParam String url, HttpServletResponse response)
            throws IOException {
        // VULN: Open redirect
        response.sendRedirect(url);
    }

    @GetMapping("/spring-redirect")
    public String springRedirect(@RequestParam String target) {
        // VULN: Open redirect via Spring redirect:
        return "redirect:" + target;
    }

    // ============ CSRF DISABLED ============
    // VULN: CSRF protection disabled (simulated Spring Security config)
    public void configure() {
        // http.csrf().disable();
    }

    // ============ MASS ASSIGNMENT ============
    @PostMapping("/user/update")
    public String updateUser(@RequestBody UserDTO user) {
        // VULN: @RequestBody without @Valid
        // Missing @Valid annotation means no bean validation
        return "User updated: " + user.toString();
    }

    // ============ MISSING INPUT VALIDATION ============
    @PostMapping("/register")
    public String register(@RequestBody RegistrationForm form) {
        // VULN: No @Valid annotation on @RequestBody
        return "Registered: " + form.toString();
    }

    // ============ XSS VIA MODEL ============
    @GetMapping("/profile")
    public String showProfile(@RequestParam String name, Model model) {
        // VULN: XSS via model attribute with tainted data
        model.addAttribute("username", name);
        return "profile";
    }

    // ============ FILE UPLOAD ============
    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // VULN: File upload without type/size validation
        String originalName = file.getOriginalFilename();
        File dest = new File("/var/uploads/" + originalName);
        file.transferTo(dest);
        return "Uploaded: " + originalName;
    }

    // ============ LOG INJECTION ============
    @GetMapping("/search")
    public String search(@RequestParam String query, HttpServletRequest request) {
        // VULN: Log injection - user input in log message
        org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(getClass());
        String userAgent = request.getHeader("User-Agent");
        logger.info("Search query: " + query + " from " + userAgent);
        return "Results for: " + query;
    }

    // ============ LDAP INJECTION ============
    @GetMapping("/ldap-search")
    public String ldapSearch(@RequestParam String username) throws NamingException {
        // VULN: LDAP injection
        DirContext ctx = new InitialDirContext();
        String filter = "(uid=" + username + ")";
        ctx.search("ou=users,dc=example,dc=com", filter, null);
        return "Found user";
    }

    // ============ SSRF VIA RESTTEMPLATE ============
    @GetMapping("/proxy")
    public String proxyRequest(@RequestParam String targetUrl) {
        // VULN: SSRF via RestTemplate
        org.springframework.web.client.RestTemplate restTemplate = new org.springframework.web.client.RestTemplate();
        String result = restTemplate.getForObject(targetUrl, String.class);
        return result;
    }

    // ============ RACE CONDITION (SINGLETON STATE) ============
    @GetMapping("/count")
    public String incrementCount() {
        // VULN: Race condition - mutable shared state in singleton
        requestCount++;
        cache.put("lastAccess", new Date());
        return "Count: " + requestCount;
    }

    // ============ TIMING ATTACK ============
    @PostMapping("/verify-token")
    public boolean verifyToken(@RequestParam String token) {
        String secretToken = "expected-secret-token-value";
        // VULN: Timing attack via String.equals on secret
        return secretToken.equals(token);
    }

    // ============ HIBERNATE HQL INJECTION ============
    public List<Object> findUsers(String name) {
        javax.persistence.EntityManager em = null; // would be injected
        // VULN: HQL injection via string concatenation
        String hql = "FROM User u WHERE u.name = '" + name + "'";
        javax.persistence.Query query = em.createQuery(hql);
        return query.getResultList();
    }

    // ============ NULL POINTER ============
    @GetMapping("/item")
    public String getItem(@RequestParam String id) {
        Map<String, String> items = new HashMap<>();
        items.put("1", "Item 1");
        // VULN: Potential null pointer - get() can return null
        String item = items.get(id);
        return item.toUpperCase();
    }

    // ============ INSECURE TLS ============
    // VULN: TrustManager that trusts all certificates
    private static class TrustAllManager implements javax.net.ssl.X509TrustManager {
        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }

        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

    // ============ HOSTNAME VERIFIER DISABLED ============
    // VULN: HostnameVerifier that always returns true
    private static class TrustAllHostnames implements javax.net.ssl.HostnameVerifier {
        public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
            return true;
        }
    }

    // ============ CODE INJECTION ============
    @PostMapping("/execute")
    public String executeScript(@RequestParam String script) throws Exception {
        // VULN: Script engine code injection
        javax.script.ScriptEngine engine = new javax.script.ScriptEngineManager().getEngineByName("nashorn");
        Object result = engine.eval(script);
        return result.toString();
    }

    // ============ JWT ISSUES ============
    public String createJwt(String userId) {
        // VULN: Weak JWT secret
        return io.jsonwebtoken.Jwts.builder()
            .setSubject(userId)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, "short")
            .compact();
    }

    // Inner class stubs
    static class UserDTO {
        private String name;
        private String email;
        private String role;
        private boolean isAdmin;
        public String toString() { return name; }
    }

    static class RegistrationForm {
        private String username;
        private String password;
        private String email;
        public String toString() { return username; }
    }
}
