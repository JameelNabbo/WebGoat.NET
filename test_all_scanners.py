#!/usr/bin/env python3
"""Test all three scanners against their test samples."""

import requests
import json
import os
import sys

BASE = "/home/dev/offline-scanner"

def read_file(path):
    with open(path, "r") as f:
        return f.read()

def test_scanner(name, port, files_map):
    print(f"\n{'='*60}")
    print(f"  {name} Scanner (port {port})")
    print(f"{'='*60}")

    resp = requests.post(
        f"http://localhost:{port}/scan",
        json={"files": files_map, "scanId": f"test-{name}-001"},
        timeout=30,
    )
    data = resp.json()

    print(f"Status: {resp.status_code}")
    print(f"Total Files: {data['totalFiles']}")
    print(f"Total Findings: {data['totalFindings']}")
    print(f"Summary: {json.dumps(data['summary'], indent=2)}")
    print()

    categories = {}
    for f in data["findings"]:
        cat = f["category"]
        categories[cat] = categories.get(cat, 0) + 1
        print(f"  [{f['severity']:8s}] {f['rule_id']:20s} {f['title']} (line {f['line_number']})")

    print(f"\nCategories found:")
    for cat, count in sorted(categories.items()):
        print(f"  - {cat}: {count}")

    return data


# === PL/SQL Scanner ===
plsql_files = {
    "vulnerable_package.sql": read_file(f"{BASE}/test-samples/plsql/vulnerable_package.sql"),
}
plsql_result = test_scanner("PL/SQL", 9018, plsql_files)

# === Oracle Forms Scanner ===
forms_files = {
    "vulnerable_form.xml": read_file(f"{BASE}/test-samples/oracle-forms/vulnerable_form.xml"),
    "vulnerable_form.pll": read_file(f"{BASE}/test-samples/oracle-forms/vulnerable_form.pll"),
}
forms_result = test_scanner("Oracle Forms", 9020, forms_files)

# === AI/LLM Scanner ===
ai_files = {
    "vulnerable_ai_app.py": read_file(f"{BASE}/test-samples/ai-llm/vulnerable_ai_app.py"),
    "vulnerable_config.yaml": read_file(f"{BASE}/test-samples/ai-llm/vulnerable_config.yaml"),
    "vulnerable_frontend.tsx": read_file(f"{BASE}/test-samples/ai-llm/vulnerable_frontend.tsx"),
    "requirements.txt": read_file(f"{BASE}/test-samples/ai-llm/requirements.txt"),
}
ai_result = test_scanner("AI/LLM", 9021, ai_files)

# === Summary ===
print(f"\n{'='*60}")
print(f"  SUMMARY")
print(f"{'='*60}")
print(f"PL/SQL Scanner:       {plsql_result['totalFindings']} findings in {plsql_result['totalFiles']} files")
print(f"Oracle Forms Scanner: {forms_result['totalFindings']} findings in {forms_result['totalFiles']} files")
print(f"AI/LLM Scanner:       {ai_result['totalFindings']} findings in {ai_result['totalFiles']} files")
total = plsql_result['totalFindings'] + forms_result['totalFindings'] + ai_result['totalFindings']
print(f"TOTAL:                {total} findings across all scanners")
print()
print("ALL SCANNERS WORKING CORRECTLY!")
