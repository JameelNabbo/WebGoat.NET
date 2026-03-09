package com.test.vulnerable;

import javax.servlet.http.*;
import org.slf4j.*;

/**
 * Log Injection Test Samples
 * Tests: Logger calls with unsanitized user input
 */
public class LogInjectionSamples {

    private static final Logger logger = LoggerFactory.getLogger(LogInjectionSamples.class);

    // 1. Direct user input in log message
    public void logUserAction(HttpServletRequest request) {
        String username = request.getParameter("user");
        logger.info("User logged in: " + username);
    }

    // 2. Log injection with newlines enabling log forging
    public void logSearch(HttpServletRequest request) {
        String query = request.getParameter("query");
        logger.info("Search query: " + query);
    }

    // 3. Exception with user data in log
    public void logError(HttpServletRequest request) {
        String input = request.getParameter("data");
        try {
            Integer.parseInt(input);
        } catch (NumberFormatException e) {
            logger.error("Failed to parse input: " + input, e);
        }
    }

    // 4. System.out log injection
    public void sysoutLog(HttpServletRequest request) {
        String action = request.getParameter("action");
        System.out.println("Action performed: " + action);
    }
}
