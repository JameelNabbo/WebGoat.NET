"""Test: Race Conditions (TOCTOU) vulnerabilities"""
import os
import tempfile

def write_if_not_exists(filepath, data):
    # TOCTOU: check then act
    if os.path.exists(filepath):
        return False
    with open(filepath, "w") as f:
        f.write(data)
    return True

def safe_delete(filepath):
    # TOCTOU: check then delete
    if os.path.isfile(filepath):
        os.remove(filepath)

def create_temp():
    # Insecure: tempfile.mktemp() has race condition
    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write("data")
    return path
