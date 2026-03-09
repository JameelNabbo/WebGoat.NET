package com.test.vulnerable;

import javax.servlet.http.*;
import java.io.*;

/**
 * Information Disclosure Test Samples
 * Tests: Stack traces in responses, debug info, verbose errors
 */
public class InfoDisclosureSamples extends HttpServlet {

    // 1. Stack trace in HTTP response
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            String id = request.getParameter("id");
            processItem(Integer.parseInt(id));
        } catch (Exception e) {
            // Exposes internal details to the client
            e.printStackTrace(response.getWriter());
        }
    }

    // 2. Verbose error message
    public void handleError(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            // some operation
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.toString());
        }
    }

    // 3. System property disclosure
    public void sysInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        PrintWriter out = response.getWriter();
        out.println("Java Version: " + System.getProperty("java.version"));
        out.println("OS: " + System.getProperty("os.name"));
        out.println("User: " + System.getProperty("user.name"));
        out.println("Home: " + System.getProperty("user.home"));
    }

    private void processItem(int id) {
        // processing logic
    }
}
