package com.example.vulnerable

import java.sql.DriverManager
import java.sql.Connection

class UserRepository(private val connection: Connection) {

    // VULN: SQL injection via string concatenation
    fun findUserById(userId: String): User? {
        val query = "SELECT * FROM users WHERE id = " + userId
        val stmt = connection.createStatement()
        val rs = stmt.executeQuery(query)
        return if (rs.next()) User(rs.getString("name")) else null
    }

    // VULN: SQL injection via string template
    fun findUserByName(name: String): User? {
        val query = "SELECT * FROM users WHERE name = '$name'"
        val rs = connection.createStatement().executeQuery(query)
        return if (rs.next()) User(rs.getString("name")) else null
    }

    // VULN: rawQuery with concatenation (Android Room)
    fun searchUsers(searchTerm: String) {
        val db = getDatabase()
        db.rawQuery("SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'", null)
    }

    // SAFE: Parameterized query
    fun findUserSafe(userId: String): User? {
        val query = "SELECT * FROM users WHERE id = ?"
        val stmt = connection.prepareStatement(query)
        stmt.setString(1, userId)
        val rs = stmt.executeQuery()
        return if (rs.next()) User(rs.getString("name")) else null
    }

    private fun getDatabase(): Any = TODO()
}

data class User(val name: String)
