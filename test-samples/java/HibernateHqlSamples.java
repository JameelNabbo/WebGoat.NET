package com.test.vulnerable;

import javax.persistence.*;
import javax.servlet.http.*;
import java.util.List;

/**
 * Hibernate-Specific Vulnerability Test Samples
 * Tests: HQL Injection via createQuery, Criteria with user input
 */
public class HibernateHqlSamples {

    @PersistenceContext
    private EntityManager entityManager;

    // 1. HQL Injection via concatenation
    public List<?> findUsers(HttpServletRequest request) {
        String role = request.getParameter("role");
        String hql = "FROM User u WHERE u.role =  + role + ";
        return entityManager.createQuery(hql).getResultList();
    }

    // 2. Native SQL injection via EntityManager
    public List<?> nativeQuery(HttpServletRequest request) {
        String table = request.getParameter("table");
        String sql = "SELECT * FROM " + table + " WHERE active = 1";
        return entityManager.createNativeQuery(sql).getResultList();
    }

    // 3. HQL with String.format
    public Object findById(HttpServletRequest request) {
        String id = request.getParameter("id");
        String hql = String.format("FROM Account a WHERE a.id = %s", id);
        return entityManager.createQuery(hql).getSingleResult();
    }

    // 4. Multiple injections in single query
    public List<?> searchProducts(HttpServletRequest request) {
        String name = request.getParameter("name");
        String category = request.getParameter("category");
        String hql = "FROM Product p WHERE p.name LIKE % + name + % AND p.category =  + category + ";
        return entityManager.createQuery(hql).getResultList();
    }

    // 5. SAFE - Parameterized HQL (should NOT flag)
    public List<?> safeSearch(HttpServletRequest request) {
        String role = request.getParameter("role");
        return entityManager.createQuery("FROM User u WHERE u.role = :role")
            .setParameter("role", role)
            .getResultList();
    }
}
