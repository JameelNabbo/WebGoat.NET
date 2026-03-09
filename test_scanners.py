#!/usr/bin/env python3
"""Test script for all three SAST scanners."""

import requests
import json
import sys


def test_scanner(name, port, sample_path):
    print("=" * 60)
    print("  {} SCANNER (port {})".format(name.upper(), port))
    print("=" * 60)

    try:
        # Health check
        health = requests.get("http://localhost:{}/health".format(port), timeout=5)
        h = health.json()
        print("Health: {} | Categories: {}".format(h["status"], h["categories"]))
    except Exception as e:
        print("Health check FAILED: {}".format(e))
        return

    try:
        with open(sample_path, "r") as f:
            code = f.read()
    except Exception as e:
        print("Could not read sample file: {}".format(e))
        return

    try:
        resp = requests.post(
            "http://localhost:{}/scan".format(port),
            json={"files": {sample_path: code}, "scanId": "{}-test-001".format(name)},
            timeout=30
        )
        result = resp.json()
    except Exception as e:
        print("Scan FAILED: {}".format(e))
        return

    fs = result.get("filesScanned", 0)
    tv = result.get("totalVulnerabilities", 0)
    sev = result.get("severitySummary", {})
    cat = result.get("categorySummary", {})

    print("Files scanned: {}".format(fs))
    print("Total vulnerabilities: {}".format(tv))
    print("")
    print("Severity Summary:")
    for s, c in sev.items():
        if c > 0:
            print("  {}: {}".format(s, c))
    print("")
    print("Category Summary:")
    for c, n in sorted(cat.items(), key=lambda x: -x[1]):
        print("  {}: {}".format(c, n))
    print("")

    vulns = result.get("vulnerabilities", [])
    print("Sample findings (first 10):")
    for v in vulns[:10]:
        print("  [{}] {} (line {})".format(
            v.get("severity", "?"),
            v.get("title", "?"),
            v.get("line_number", "?")
        ))
    if len(vulns) > 10:
        print("  ... and {} more".format(len(vulns) - 10))

    print("")
    errors = result.get("errors", [])
    if errors:
        print("Errors: {}".format(json.dumps(errors, indent=2)))
    else:
        print("No errors.")

    print("")
    return tv


if __name__ == "__main__":
    results = {}

    results["swift"] = test_scanner(
        "swift", 9010,
        "/home/dev/offline-scanner/test-samples/swift/VulnerableApp.swift"
    )

    results["objc"] = test_scanner(
        "objc", 9011,
        "/home/dev/offline-scanner/test-samples/objc/VulnerableApp.m"
    )

    results["dart"] = test_scanner(
        "dart", 9013,
        "/home/dev/offline-scanner/test-samples/dart/vulnerable_app.dart"
    )

    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    for scanner, count in results.items():
        status = "PASS" if count and count > 0 else "FAIL"
        print("  {} scanner: {} vulnerabilities found [{}]".format(
            scanner.upper(), count if count else 0, status))
    print("")
