package com.test.vulnerable;

import java.sql.*;
import javax.servlet.http.*;
import javax.persistence.*;

/**
 * SQL Injection Test Samples
 * Tests: JDBC Statement concatenation, PreparedStatement misuse,
 *        String.format in SQL, JPA native queries
 */
public class SqlInjectionSamples {

    private Connection conn;

    // 1. Classic JDBC Statement concatenation
    public ResultSet searchUsers(HttpServletRequest request) throws SQLException {
        String username = request.getParameter("username");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = ' + username + '";
        return stmt.executeQuery(query);
    }

    // 2. PreparedStatement misuse - concatenation instead of parameterization
    public ResultSet badPreparedStatement(HttpServletRequest request) throws SQLException {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM orders WHERE order_id = " + id;
        PreparedStatement pstmt = conn.prepareStatement(sql);
        return pstmt.executeQuery();
    }

    // 3. String.format SQL injection
    public void updateUser(HttpServletRequest request) throws SQLException {
        String email = request.getParameter("email");
        String userId = request.getParameter("userId");
        Statement stmt = conn.createStatement();
        stmt.executeUpdate(String.format("UPDATE users SET email = '%s' WHERE id = %s", email, userId));
    }

    // 4. executeQuery with direct concatenation
    public ResultSet getProducts(HttpServletRequest request) throws SQLException {
        String category = request.getParameter("category");
        String sort = request.getParameter("sort");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM products WHERE category = ' + category + ' ORDER BY " + sort);
    }

    // 5. Batch SQL injection
    public void batchInsert(HttpServletRequest request) throws SQLException {
        String data = request.getParameter("data");
        Statement stmt = conn.createStatement();
        stmt.addBatch("INSERT INTO logs (message) VALUES (' + data + ')" );
        stmt.executeBatch();
    }

    // 6. SAFE - Proper PreparedStatement usage (should NOT flag)
    public ResultSet safeQuery(HttpServletRequest request) throws SQLException {
        String username = request.getParameter("username");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        pstmt.setString(1, username);
        return pstmt.executeQuery();
    }
}
