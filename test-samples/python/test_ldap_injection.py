"""Test: LDAP Injection vulnerabilities"""
import ldap
from flask import Flask, request

app = Flask(__name__)

@app.route("/search_user")
def search_user():
    username = request.args.get("username")
    
    conn = ldap.initialize("ldap://localhost")
    conn.simple_bind_s("cn=admin,dc=example,dc=com", "password")
    
    # LDAP injection via string concatenation
    results = conn.search_s(
        "dc=example,dc=com",
        ldap.SCOPE_SUBTREE,
        "(uid=" + username + ")"
    )
    
    # LDAP injection via f-string
    filter_str = f"(&(uid={username})(objectClass=person))"
    results2 = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
    
    return str(results)
