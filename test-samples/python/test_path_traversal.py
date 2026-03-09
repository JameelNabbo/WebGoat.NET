"""Test: Path Traversal vulnerabilities"""
import os
import shutil
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route("/download")
def download():
    filename = request.args.get("file")
    
    # Path traversal via open
    with open("/var/data/" + filename, "r") as f:
        content = f.read()
    
    # Path traversal via os.path.join
    path = os.path.join("/uploads", filename)
    
    # Path traversal via send_file
    return send_file(path)

@app.route("/copy")
def copy_file():
    src = request.args.get("src")
    dst = request.args.get("dst")
    # Path traversal via shutil
    shutil.copy(src, dst)
    return "Copied"
