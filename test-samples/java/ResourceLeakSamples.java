package com.test.vulnerable;

import java.io.*;
import java.sql.*;
import java.net.*;

/**
 * Resource Leak Test Samples
 * Tests: Unclosed streams, connections, sockets
 */
public class ResourceLeakSamples {

    // 1. FileInputStream not closed
    public byte[] readFile(String path) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[1024];
        fis.read(data);
        return data;  // fis never closed - resource leak
    }

    // 2. Database connection not closed
    public String queryData(String sql) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        rs.next();
        return rs.getString(1);
        // conn, stmt, rs never closed
    }

    // 3. BufferedReader not closed
    public String readFirstLine(String filename) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        return reader.readLine();
        // reader never closed
    }

    // 4. Socket not closed
    public void sendData(String host, int port, String data) throws Exception {
        Socket socket = new Socket(host, port);
        OutputStream out = socket.getOutputStream();
        out.write(data.getBytes());
        out.flush();
        // socket never closed
    }

    // 5. SAFE - try-with-resources (should NOT flag)
    public String safeRead(String path) throws Exception {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            return br.readLine();
        }
    }
}
