package com.test.vulnerable;

import javax.servlet.http.*;
import java.io.*;

/**
 * Cross-Site Scripting (XSS) Test Samples
 * Tests: Reflected XSS via servlet response, direct parameter output
 */
public class XssSamples extends HttpServlet {

    // 1. Reflected XSS - direct parameter to response
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Welcome " + name + "</h1>");
        out.println("</body></html>");
    }

    // 2. XSS via getWriter().write()
    public void writeXss(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String query = request.getParameter("q");
        response.getWriter().write("<div>Search results for: " + query + "</div>");
    }

    // 3. XSS via error message
    public void errorXss(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("data");
        response.sendError(400, "Invalid input: " + input);
    }

    // 4. XSS via header injection
    public void headerXss(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String redirect = request.getParameter("url");
        response.setHeader("Location", redirect);
    }

    // 5. Stored XSS - tainted data in model attribute
    public String modelXss(HttpServletRequest request, org.springframework.ui.Model model) {
        String comment = request.getParameter("comment");
        model.addAttribute("userComment", comment);
        return "view";
    }
}
