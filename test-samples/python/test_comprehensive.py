"""Test: Comprehensive vulnerability test file covering remaining categories"""
from flask import Flask, request, redirect
from django.views.decorators.csrf import csrf_exempt
import subprocess
import os
import random
import hashlib
import logging
import re

app = Flask(__name__)
logger = logging.getLogger(__name__)

# ===== 13. Debug Mode =====
DEBUG = True

# ===== 30. Django CSRF disabled =====
@csrf_exempt
def payment_view(request):
    return None

# ===== 14. Missing Authentication =====
@app.post("/admin/delete-user")
def delete_user():
    user_id = request.form.get("user_id")
    return f"Deleted {user_id}"

# ===== 16. Insecure File Upload =====
@app.route("/upload", methods=["POST"])
def upload_file():
    uploaded = request.files.get("document")
    if uploaded:
        uploaded.save(f"/var/uploads/{uploaded.filename}")
    return "OK"

# ===== 22. Security Misconfiguration =====
app.run(debug=True, host="0.0.0.0")

# ===== 24. Insufficient Input Validation =====
@app.route("/process")
def process():
    data = request.form.get("data")
    amount = request.args.get("amount")
    # No validation at all - directly used
    result = int(amount) * 2
    return str(result)

# ===== 26. ReDoS =====
evil_regex = re.compile(r"(a+)+$")

# ===== 29. Timing Attacks =====
def check_secret(user_secret, real_secret):
    return user_secret == real_secret

# ===== 31. Flask weak secret =====
app.secret_key = "abc"

# ===== 35. subprocess without shell=False =====
def run_command(cmd):
    subprocess.call(cmd, shell=True)

# ===== 36. Temp file issues =====
import tempfile
tmp = tempfile.mktemp()

# ===== 37. SSL disabled =====
import requests
requests.get("https://api.example.com", verify=False)

# ===== 38. Cleartext credentials =====
db_password = "RealProductionPassword123!"
api_secret = "sk-prod-1234567890abcdefghijklmnop"

# ===== 39. Insufficient logging =====
try:
    risky_operation = 1 / 0
except Exception:
    pass

# ===== 27. Integer overflow =====
import ctypes
val = ctypes.c_int(2**31)

# ===== 12. Insecure random =====
session_token = random.randint(0, 2**32)

# ===== 11. Weak crypto =====
password_hash = hashlib.md5(b"password").hexdigest()

# ===== 23. Logging sensitive data =====
def login(username, password):
    logger.info(f"User {username} login with password: {password}")
