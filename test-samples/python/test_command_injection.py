"""Test: Command Injection vulnerabilities"""
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    
    # Command injection via os.system
    os.system("ping -c 1 " + host)
    
    # Command injection via os.popen
    result = os.popen(f"nslookup {host}").read()
    
    # subprocess with shell=True and user input
    subprocess.call("ls " + host, shell=True)
    
    # subprocess.run with shell=True
    subprocess.run(f"dig {host}", shell=True)
    
    # subprocess.check_output with shell=True
    output = subprocess.check_output("whois " + host, shell=True)
    
    return result
