"""Test: Debug Mode and Security Misconfiguration"""
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# Debug mode enabled
DEBUG = True

# Flask debug in app.run
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

# CORS allow all
CORS(app, origins="*")

# Weak secret key
app.secret_key = "dev"
