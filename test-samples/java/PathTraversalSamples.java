package com.test.vulnerable;

import javax.servlet.http.*;
import java.io.*;
import java.nio.file.*;

/**
 * Path Traversal Test Samples
 * Tests: File with user input, FileInputStream, Paths.get
 */
public class PathTraversalSamples {

    // 1. Basic File path traversal
    public void readFile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fileName = request.getParameter("file");
        File file = new File("/uploads/" + fileName);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = fis.readAllBytes();
        response.getOutputStream().write(data);
        fis.close();
    }

    // 2. FileReader with user input
    public String readContent(HttpServletRequest request) throws Exception {
        String path = request.getParameter("path");
        FileReader reader = new FileReader(path);
        BufferedReader br = new BufferedReader(reader);
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            content.append(line);
        }
        br.close();
        return content.toString();
    }

    // 3. Paths.get with user input
    public byte[] getFile(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("filename");
        Path path = Paths.get("/data/documents", filename);
        return Files.readAllBytes(path);
    }

    // 4. Path.resolve with user input
    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        Path basePath = Paths.get("/var/files");
        Path filePath = basePath.resolve(name);
        Files.copy(filePath, response.getOutputStream());
    }

    // 5. RandomAccessFile with user input
    public void randomAccess(HttpServletRequest request) throws Exception {
        String target = request.getParameter("target");
        RandomAccessFile raf = new RandomAccessFile(target, "r");
        System.out.println(raf.readLine());
        raf.close();
    }
}
