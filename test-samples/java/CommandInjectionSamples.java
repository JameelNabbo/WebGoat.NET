package com.test.vulnerable;

import javax.servlet.http.*;
import java.io.*;

/**
 * Command Injection Test Samples
 * Tests: Runtime.exec(), ProcessBuilder with user input
 */
public class CommandInjectionSamples {

    // 1. Runtime.exec with user input
    public String runCommand(HttpServletRequest request) throws Exception {
        String hostname = request.getParameter("host");
        Process process = Runtime.getRuntime().exec("ping -c 4 " + hostname);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // 2. ProcessBuilder with tainted input
    public void processFile(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("file");
        ProcessBuilder pb = new ProcessBuilder("cat", filename);
        pb.start();
    }

    // 3. Runtime.exec with array and concatenation
    public void execWithArray(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        String[] command = {"/bin/sh", "-c", cmd};
        Runtime.getRuntime().exec(command);
    }

    // 4. Indirect command injection via variable
    public void indirectExec(HttpServletRequest request) throws Exception {
        String userInput = request.getParameter("action");
        String command = "ls -la " + userInput;
        Runtime.getRuntime().exec(command);
    }

    // 5. ProcessBuilder.command() with user input
    public void pbCommand(HttpServletRequest request) throws Exception {
        String tool = request.getParameter("tool");
        ProcessBuilder pb = new ProcessBuilder();
        pb.command("sh", "-c", tool);
        pb.start();
    }
}
