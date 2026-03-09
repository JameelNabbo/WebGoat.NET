package com.test.vulnerable;

import javax.naming.*;
import javax.naming.directory.*;
import javax.servlet.http.*;
import java.util.*;

/**
 * LDAP Injection Test Samples
 * Tests: DirContext.search with user input in filter
 */
public class LdapInjectionSamples {

    private DirContext ctx;

    // 1. LDAP search with concatenated filter
    public NamingEnumeration<?> searchUser(HttpServletRequest request) throws Exception {
        String username = request.getParameter("username");
        String filter = "(&(uid=" + username + ")(objectClass=person))";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        return ctx.search("dc=example,dc=com", filter, controls);
    }

    // 2. LDAP lookup with user input
    public Object lookupUser(HttpServletRequest request) throws Exception {
        String dn = request.getParameter("dn");
        return ctx.lookup(dn);
    }

    // 3. String.format in LDAP filter
    public NamingEnumeration<?> formatFilter(HttpServletRequest request) throws Exception {
        String email = request.getParameter("email");
        String filter = String.format("(mail=%s)", email);
        return ctx.search("ou=users,dc=corp,dc=com", filter, new SearchControls());
    }

    // 4. Multiple user inputs in LDAP filter
    public NamingEnumeration<?> multiSearch(HttpServletRequest request) throws Exception {
        String dept = request.getParameter("department");
        String role = request.getParameter("role");
        String filter = "(&(department=" + dept + ")(role=" + role + "))";
        return ctx.search("dc=company,dc=com", filter, new SearchControls());
    }
}
