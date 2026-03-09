#!/usr/bin/env python3
"""
SAST Scanner - Real Project Vulnerability Scanner
Scans downloaded vulnerable projects against local SAST scanner engines.
"""

import os
import sys
import json
import uuid
import time
import requests
from pathlib import Path
from datetime import datetime

# === Configuration ===
BASE_DIR = "/home/dev/offline-scanner/test-projects"
RESULTS_DIR = "/home/dev/offline-scanner/scan-results"
SCANNER_BASE = "http://127.0.0.1"
BATCH_SIZE = 50
REQUEST_TIMEOUT = 120  # seconds per batch

# Scanner port mapping by language
SCANNERS = {
    "python":     {"port": 9001, "extensions": {".py"}},
    "javascript": {"port": 9002, "extensions": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}},
    "csharp":     {"port": 9003, "extensions": {".cs"}},
    "java":       {"port": 9004, "extensions": {".java", ".jsp"}},
    "go":         {"port": 9005, "extensions": {".go"}},
    "php":        {"port": 9006, "extensions": {".php"}},
    "ruby":       {"port": 9007, "extensions": {".rb", ".erb"}},
}

# Project -> scanner language mapping
PROJECTS = [
    {"name": "Vulnerable-Flask-App", "language": "python"},
    {"name": "dvpwa",                "language": "python"},
    {"name": "vulnerable-node",      "language": "javascript"},
    {"name": "vuln-nodejs-app",      "language": "javascript"},
    {"name": "WebGoat",              "language": "java"},
    {"name": "JavaVulnerableLab",    "language": "java"},
    {"name": "vuln-dotnet-alt",      "language": "java"},      # Actually a Java project (VulnerableApp/SASanLabs)
    {"name": "WebGoat.Net",          "language": "csharp"},
    {"name": "govwa",                "language": "go"},
    {"name": "DVWA",                 "language": "php"},
    {"name": "railsgoat",            "language": "ruby"},
    # Benchmark excluded - only has README.md, no source files
]

# Directories and files to skip
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".idea", ".vscode",
    ".gradle", "build", "target", "bin", "obj", "dist", ".settings",
    "gradle", ".github", "docs", "doc", "metrics", "test-output"
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".o", ".class", ".jar", ".war",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo", ".DS_Store", ".swf",
    ".map", ".min.js", ".min.css",
}

# Binary content detection
BINARY_CHARS = bytes(range(0, 8)) + bytes(range(14, 32))


def is_binary(file_path, chunk_size=8192):
    """Check if a file appears to be binary."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(chunk_size)
            if b"\x00" in chunk:
                return True
            if any(byte in BINARY_CHARS for byte in chunk[:512]):
                return True
        return False
    except (IOError, OSError):
        return True


def collect_source_files(project_dir, extensions):
    """Collect all source files matching the given extensions."""
    files = {}
    project_path = Path(project_dir)

    for root, dirs, filenames in os.walk(project_path):
        # Skip unwanted directories (modify dirs in-place to prevent descent)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in filenames:
            file_path = Path(root) / filename
            ext = file_path.suffix.lower()

            # Skip non-matching extensions
            if ext not in extensions:
                continue

            # Skip known binary/unwanted extensions
            if ext in SKIP_EXTENSIONS:
                continue

            # Skip very large files (>500KB)
            try:
                size = file_path.stat().st_size
                if size > 500_000:
                    continue
                if size == 0:
                    continue
            except OSError:
                continue

            # Skip binary files
            if is_binary(str(file_path)):
                continue

            # Read file content
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                # Use relative path from project root
                rel_path = str(file_path.relative_to(project_path))
                files[rel_path] = content
            except (IOError, OSError, UnicodeDecodeError) as e:
                print(f"    [WARN] Could not read {file_path}: {e}")
                continue

    return files


def scan_files(files, scanner_port, scan_id=None):
    """Send files to scanner in batches and collect all vulnerabilities."""
    if scan_id is None:
        scan_id = str(uuid.uuid4())

    all_vulns = []
    all_errors = []
    total_files_scanned = 0
    file_items = list(files.items())

    for batch_start in range(0, len(file_items), BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, len(file_items))
        batch_files = dict(file_items[batch_start:batch_end])
        batch_num = (batch_start // BATCH_SIZE) + 1
        total_batches = (len(file_items) + BATCH_SIZE - 1) // BATCH_SIZE

        print(f"    Batch {batch_num}/{total_batches}: {len(batch_files)} files...", end=" ", flush=True)

        payload = {
            "files": batch_files,
            "scanId": scan_id
        }

        try:
            url = f"{SCANNER_BASE}:{scanner_port}/scan"
            response = requests.post(
                url,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                result = response.json()
                vulns = result.get("vulnerabilities", [])
                errors = result.get("errors", []) or []
                scanned = result.get("filesScanned", len(batch_files))

                all_vulns.extend(vulns)
                all_errors.extend(errors)
                total_files_scanned += scanned
                print(f"{len(vulns)} vulns found")
            else:
                print(f"HTTP {response.status_code}: {response.text[:200]}")
                all_errors.append(f"Batch {batch_num}: HTTP {response.status_code}")

        except requests.exceptions.Timeout:
            print("TIMEOUT")
            all_errors.append(f"Batch {batch_num}: Request timed out after {REQUEST_TIMEOUT}s")
        except requests.exceptions.ConnectionError as e:
            print(f"CONNECTION ERROR: {e}")
            all_errors.append(f"Batch {batch_num}: Connection error")
        except Exception as e:
            print(f"ERROR: {e}")
            all_errors.append(f"Batch {batch_num}: {str(e)}")

    return all_vulns, all_errors, total_files_scanned


def categorize_severity(vulns):
    """Count vulnerabilities by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = v.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
        elif sev == "information" or sev == "informational":
            counts["info"] += 1
        else:
            counts["low"] += 1  # Unknown severity -> low
    return counts


def get_categories(vulns):
    """Extract unique vulnerability categories."""
    categories = set()
    for v in vulns:
        cat = v.get("category", "")
        if cat:
            categories.add(cat)
    return sorted(categories)


def get_cwes(vulns):
    """Extract unique CWE identifiers."""
    cwes = set()
    for v in vulns:
        cwe = v.get("cwe", "")
        if cwe:
            cwes.add(cwe)
    return sorted(cwes)


def save_project_result(project_name, result):
    """Save detailed scan result for a project."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, f"{project_name}.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return output_path


def main():
    print("=" * 80)
    print("SAST Real Project Vulnerability Scanner")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Verify scanners are available
    print("\n[1/3] Checking scanner availability...")
    scanner_status = {}
    for lang, config in SCANNERS.items():
        port = config["port"]
        try:
            r = requests.get(f"{SCANNER_BASE}:{port}/health", timeout=5)
            if r.status_code == 200:
                scanner_status[lang] = "OK"
                print(f"  {lang:12s} (port {port}): AVAILABLE")
            else:
                scanner_status[lang] = "ERROR"
                print(f"  {lang:12s} (port {port}): ERROR (HTTP {r.status_code})")
        except Exception as e:
            scanner_status[lang] = "DOWN"
            print(f"  {lang:12s} (port {port}): DOWN ({e})")

    # Scan each project
    print(f"\n[2/3] Scanning {len(PROJECTS)} projects...")
    print("-" * 80)

    all_results = []

    for idx, project in enumerate(PROJECTS, 1):
        name = project["name"]
        language = project["language"]
        scanner_config = SCANNERS[language]
        port = scanner_config["port"]
        extensions = scanner_config["extensions"]

        project_dir = os.path.join(BASE_DIR, name)

        print(f"\n[{idx}/{len(PROJECTS)}] {name} ({language}, port {port})")

        # Check project directory exists
        if not os.path.isdir(project_dir):
            print(f"  SKIPPED: Directory not found: {project_dir}")
            all_results.append({
                "project": name,
                "language": language,
                "status": "SKIPPED",
                "error": "Directory not found"
            })
            continue

        # Check scanner is available
        if scanner_status.get(language) != "OK":
            print(f"  SKIPPED: Scanner for {language} is not available")
            all_results.append({
                "project": name,
                "language": language,
                "status": "SKIPPED",
                "error": f"Scanner not available"
            })
            continue

        # Collect source files
        print(f"  Collecting {', '.join(extensions)} files...")
        source_files = collect_source_files(project_dir, extensions)
        file_count = len(source_files)

        if file_count == 0:
            print(f"  SKIPPED: No matching source files found")
            all_results.append({
                "project": name,
                "language": language,
                "status": "SKIPPED",
                "error": "No matching source files",
                "files_found": 0
            })
            continue

        print(f"  Found {file_count} source files")

        # Run scan
        scan_id = str(uuid.uuid4())
        start_time = time.time()
        vulns, errors, files_scanned = scan_files(source_files, port, scan_id)
        duration = time.time() - start_time

        # Analyze results
        severity_counts = categorize_severity(vulns)
        categories = get_categories(vulns)
        cwes = get_cwes(vulns)

        result = {
            "project": name,
            "language": language,
            "scanner_port": port,
            "scan_id": scan_id,
            "status": "COMPLETED",
            "timestamp": datetime.now().isoformat(),
            "files_collected": file_count,
            "files_scanned": files_scanned,
            "scan_duration_seconds": round(duration, 2),
            "total_vulnerabilities": len(vulns),
            "severity_counts": severity_counts,
            "vulnerability_categories": categories,
            "cwes_found": cwes,
            "vulnerabilities": vulns,
            "errors": errors
        }

        # Save per-project result
        output_path = save_project_result(name, result)
        print(f"  DONE: {len(vulns)} vulnerabilities in {duration:.1f}s -> {output_path}")

        # Summary for table (without full vuln details)
        summary = {k: v for k, v in result.items() if k != "vulnerabilities"}
        all_results.append(summary)

    # === Summary ===
    print("\n" + "=" * 80)
    print("[3/3] SCAN RESULTS SUMMARY")
    print("=" * 80)

    # Header
    header = f"{'Project':<25} | {'Language':<12} | {'Files':>5} | {'Vulns':>5} | {'Crit':>4} | {'High':>4} | {'Med':>4} | {'Low':>4} | {'Duration':>8}"
    print(header)
    print("-" * len(header))

    total_vulns = 0
    total_files = 0
    total_crit = 0
    total_high = 0
    total_med = 0
    total_low = 0

    for r in all_results:
        if r.get("status") == "SKIPPED":
            print(f"{r['project']:<25} | {r['language']:<12} | {'---':>5} | {'SKIPPED':>5} | {'':>4} | {'':>4} | {'':>4} | {'':>4} | {'---':>8}")
            continue

        sev = r.get("severity_counts", {})
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        med = sev.get("medium", 0)
        low = sev.get("low", 0)
        info = sev.get("info", 0)
        vulns = r.get("total_vulnerabilities", 0)
        files = r.get("files_collected", 0)
        dur = r.get("scan_duration_seconds", 0)

        total_vulns += vulns
        total_files += files
        total_crit += crit
        total_high += high
        total_med += med
        total_low += low

        print(f"{r['project']:<25} | {r['language']:<12} | {files:>5} | {vulns:>5} | {crit:>4} | {high:>4} | {med:>4} | {low:>4} | {dur:>7.1f}s")

    print("-" * len(header))
    print(f"{'TOTAL':<25} | {'':12} | {total_files:>5} | {total_vulns:>5} | {total_crit:>4} | {total_high:>4} | {total_med:>4} | {total_low:>4} |")
    print()

    # Category breakdown
    print("\n=== Vulnerability Categories by Project ===")
    for r in all_results:
        if r.get("status") == "SKIPPED":
            continue
        cats = r.get("vulnerability_categories", [])
        if cats:
            print(f"\n  {r['project']} ({r['total_vulnerabilities']} vulns):")
            for cat in cats:
                # Count vulns in this category (from saved file)
                print(f"    - {cat}")

    # CWE breakdown
    print("\n\n=== CWEs Found by Project ===")
    for r in all_results:
        if r.get("status") == "SKIPPED":
            continue
        cwes = r.get("cwes_found", [])
        if cwes:
            print(f"\n  {r['project']}:")
            for cwe in cwes:
                print(f"    - {cwe}")

    # Save overall summary
    summary_path = os.path.join(RESULTS_DIR, "_summary.json")
    summary_data = {
        "scan_date": datetime.now().isoformat(),
        "total_projects_scanned": sum(1 for r in all_results if r.get("status") == "COMPLETED"),
        "total_projects_skipped": sum(1 for r in all_results if r.get("status") == "SKIPPED"),
        "total_files_scanned": total_files,
        "total_vulnerabilities": total_vulns,
        "total_critical": total_crit,
        "total_high": total_high,
        "total_medium": total_med,
        "total_low": total_low,
        "per_project": all_results
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2, default=str)
    print(f"\nOverall summary saved to: {summary_path}")

    print(f"\nCompleted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
