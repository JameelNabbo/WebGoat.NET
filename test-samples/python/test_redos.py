"""Test: ReDoS vulnerabilities"""
import re

# Vulnerable regex patterns
email_pattern = re.compile(r"^([a-zA-Z0-9]+)*@example\.com$")
url_pattern = re.compile(r"^(https?://[^\s]+)*$")

def validate_input(text):
    # ReDoS: nested quantifier
    if re.match(r"(a+)+b", text):
        return True
    
    # ReDoS: alternation with quantifier
    if re.match(r"(a|b+)*c", text):
        return True
    
    return False
