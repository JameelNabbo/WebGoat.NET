#!/usr/bin/env python3
"""Test script for C/C++ SAST Scanner"""
import json
import sys

try:
    import requests
except ImportError:
    import urllib.request
    import urllib.parse

    def post_json(url, data):
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        resp = urllib.request.urlopen(req, timeout=120)
        return json.loads(resp.read().decode('utf-8'))

    def get_json(url):
        resp = urllib.request.urlopen(url, timeout=10)
        return json.loads(resp.read().decode('utf-8'))

    HAS_REQUESTS = False
else:
    HAS_REQUESTS = True

    def post_json(url, data):
        resp = requests.post(url, json=data, timeout=120)
        resp.raise_for_status()
        return resp.json()

    def get_json(url):
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()


BASE = "http://localhost:9008"

# Health check
print("=== HEALTH CHECK ===")
health = get_json(BASE + "/health")
print(json.dumps(health, indent=2))
print()

# Read test files
files = {}
for path in [
    "/home/dev/offline-scanner/test-samples/cpp/test_vulnerable.c",
    "/home/dev/offline-scanner/test-samples/cpp/test_vulnerable.cpp",
]:
    try:
        with open(path, "r") as f:
            content = f.read()
        name = path.split("/")[-1]
        files[name] = content
        print("Loaded: %s (%d bytes)" % (name, len(content)))
    except Exception as e:
        print("Failed to load %s: %s" % (path, e))

if not files:
    print("No files loaded!")
    sys.exit(1)

# Run scan
print("\n=== SCANNING %d files ===" % len(files))
result = post_json(BASE + "/scan", {"files": files, "scanId": "test-001"})

tf = result["totalFiles"]
tfi = result["totalFindings"]
print("Files scanned: %d" % tf)
print("Total findings: %d" % tfi)
print("\nSeverity breakdown:")
for sev in ["Critical", "High", "Medium", "Low", "Info"]:
    count = result["summary"].get(sev, 0)
    if count > 0:
        print("  %-8s: %d" % (sev, count))

# Group by category
categories = {}
for f in result["findings"]:
    cat = f["category"]
    if cat not in categories:
        categories[cat] = []
    categories[cat].append(f)

print("\n=== FINDINGS BY CATEGORY (%d categories) ===" % len(categories))
for cat in sorted(categories.keys()):
    items = categories[cat]
    print("\n[%2d] %s" % (len(items), cat))
    for item in items[:5]:
        ln = item["line_number"]
        sev = item["severity"]
        fp = item["file_path"]
        title = item["title"][:65]
        cwe = item.get("cwe_id", "")
        print("     %s:%3d | %-8s | %-6s | %s" % (fp, ln, sev, cwe, title))
    if len(items) > 5:
        print("     ... and %d more" % (len(items) - 5))

# Verify coverage of required categories
required = [
    "Buffer Overflow", "Format String", "Integer Overflow", "Use After Free",
    "Double Free", "Null Pointer Dereference", "Memory Leaks", "Stack Overflow",
    "Command Injection", "SQL Injection", "Path Traversal", "Race Condition",
    "Hardcoded Secrets", "Weak Cryptography", "Insecure Random",
    "Uninitialized Variables", "Array Out of Bounds", "Type Confusion",
    "Signal Handler Issues", "File Permission Issues", "Privilege Escalation",
    "Information Disclosure", "Missing Input Validation", "Unsafe String Operations",
    "Thread Safety", "Compiler Warnings", "Resource Leaks",
    "Embedded/IoT Specific", "Code Quality",
]

print("\n=== COVERAGE CHECK ===")
found_cats = set(categories.keys())
covered = 0
missing = []
for req in required:
    if req in found_cats:
        covered += 1
        print("  [OK] %s (%d findings)" % (req, len(categories[req])))
    else:
        missing.append(req)
        print("  [--] %s (not detected)" % req)

print("\nCoverage: %d/%d categories (%d%%)" % (covered, len(required), 100*covered//len(required)))
if missing:
    print("Missing: %s" % ", ".join(missing))

print("\n=== DONE ===")
