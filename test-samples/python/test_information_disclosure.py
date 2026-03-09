"""Test: Information Disclosure vulnerabilities"""
import traceback
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/data")
def get_data():
    try:
        result = 1 / 0
    except Exception as e:
        # Information disclosure: stack trace exposure
        traceback.print_exc()
        error_details = traceback.format_exc()
        return f"Error: {error_details}", 500
    
    try:
        data = {"key": "value"}
    except:
        # Bare except - may leak info
        pass
    
    return "OK"
