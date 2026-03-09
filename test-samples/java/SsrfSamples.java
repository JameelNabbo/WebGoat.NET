package com.test.vulnerable;

import javax.servlet.http.*;
import java.net.*;
import java.io.*;

/**
 * Server-Side Request Forgery (SSRF) Test Samples
 * Tests: URL, HttpURLConnection, HttpClient with user input
 */
public class SsrfSamples {

    // 1. URL with user-controlled input
    public String fetchUrl(HttpServletRequest request) throws Exception {
        String targetUrl = request.getParameter("url");
        URL url = new URL(targetUrl);
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }

    // 2. HttpURLConnection with user input
    public int checkStatus(HttpServletRequest request) throws Exception {
        String endpoint = request.getParameter("endpoint");
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        return conn.getResponseCode();
    }

    // 3. URL constructed via concatenation
    public String apiProxy(HttpServletRequest request) throws Exception {
        String service = request.getParameter("service");
        String path = request.getParameter("path");
        URL url = new URL("http://" + service + "/" + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        return br.readLine();
    }

    // 4. URI-based SSRF
    public void uriSsrf(HttpServletRequest request) throws Exception {
        String target = request.getParameter("target");
        URI uri = new URI(target);
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.connect();
    }
}
