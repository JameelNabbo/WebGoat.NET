package com.test.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.*;

/**
 * Spring-Specific Vulnerability Test Samples
 * Tests: SpEL Injection, CORS Misconfiguration, CSRF Disabled,
 *        Actuator Exposure, Mass Assignment, Open Redirect
 */
@EnableWebSecurity
public class SpringSecuritySamples {

    // 1. Spring Expression Language (SpEL) Injection
    @GetMapping("/eval")
    public String spelInjection(@RequestParam String expression) {
        SpelExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expression);
        return exp.getValue().toString();
    }

    // 2. CORS allow all origins
    @CrossOrigin(origins = "*")
    @GetMapping("/api/data")
    public String corsWildcard() {
        return "sensitive data";
    }

    // 3. CSRF Disabled in security config
    public void configureSecurity(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated();
    }

    // 4. Actuator endpoints exposed
    // In application.properties: management.endpoints.web.exposure.include=*

    // 5. Mass Assignment - binding all parameters
    @PostMapping("/user/update")
    public String updateUser(@ModelAttribute UserProfile profile) {
        // Dangerous: binds all request params including isAdmin, role, etc.
        return "updated";
    }

    // 6. Open Redirect
    @GetMapping("/redirect")
    public String openRedirect(@RequestParam String url) {
        return "redirect:" + url;
    }

    // 7. Open Redirect via sendRedirect
    public void redirectVuln(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("returnUrl");
        response.sendRedirect(target);
    }

    // Helper class for mass assignment
    public static class UserProfile {
        private String name;
        private String email;
        private boolean isAdmin;
        private String role;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public boolean isAdmin() { return isAdmin; }
        public void setAdmin(boolean admin) { isAdmin = admin; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }
}
