#!/usr/bin/env python3
"""
AI-Powered SAST Finding Verification
=====================================
Uses Claude AI to verify scanner findings and identify false positives.

For each project scan result, takes a sample of vulnerabilities (up to 10 per
project) and sends them to Claude for verdict: TRUE_POSITIVE, FALSE_POSITIVE,
or UNCERTAIN.

Produces a comprehensive summary with per-scanner and per-category false
positive rates.

Output: /home/dev/offline-scanner/scan-results/ai_verification.json
"""

import json
import os
import sys
import time
import random
import traceback
from datetime import datetime, timezone
from collections import defaultdict

# ---------------------------------------------------------------------------
# Anthropic SDK
# ---------------------------------------------------------------------------
try:
    import anthropic
except ImportError:
    print("ERROR: anthropic package not installed. Run: pip3 install --user anthropic")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_KEY = "ANTHROPIC_API_KEY_PLACEHOLDER"
MODEL = "claude-sonnet-4-20250514"
RESULTS_DIR = "/home/dev/offline-scanner/scan-results"
OUTPUT_FILE = os.path.join(RESULTS_DIR, "ai_verification.json")
MAX_VULNS_PER_PROJECT = 10
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_scan_results():
    """Load all project scan result JSON files."""
    results = []
    for fname in sorted(os.listdir(RESULTS_DIR)):
        if fname.endswith(".json") and fname not in ("_summary.json", "ai_verification.json"):
            fpath = os.path.join(RESULTS_DIR, fname)
            try:
                with open(fpath, "r") as f:
                    data = json.load(f)
                if data.get("total_vulnerabilities", 0) > 0:
                    results.append(data)
            except Exception as e:
                print("  WARNING: Could not load {}: {}".format(fname, e))
    return results


def sample_vulnerabilities(project_data, max_n=MAX_VULNS_PER_PROJECT):
    """
    Sample up to max_n vulnerabilities from a project, prioritising diversity:
    - Mix of severities
    - Mix of categories/CWEs
    """
    vulns = project_data.get("vulnerabilities", [])
    if not vulns:
        return []

    if len(vulns) <= max_n:
        return vulns

    # Group by category to ensure diversity
    by_category = defaultdict(list)
    for v in vulns:
        cat = v.get("category", "Unknown")
        by_category[cat].append(v)

    # Round-robin pick from each category
    selected = []
    categories = list(by_category.keys())
    random.shuffle(categories)
    idx = 0
    while len(selected) < max_n:
        cat = categories[idx % len(categories)]
        cat_vulns = by_category[cat]
        if cat_vulns:
            selected.append(cat_vulns.pop(0))
        else:
            # Remove exhausted category
            categories.remove(cat)
            if not categories:
                break
        idx += 1

    return selected


def build_verification_prompt(vuln, project_name, language):
    """Build the Claude AI verification prompt for a single vulnerability."""
    file_path = vuln.get("filePath", "unknown")
    line_number = vuln.get("lineNumber", "?")
    code_snippet = vuln.get("codeSnippet", "(no code available)")
    title = vuln.get("title", "Unknown vulnerability")
    severity = vuln.get("severity", "Unknown")
    cwe = vuln.get("cwe", "Unknown")
    remediation = vuln.get("remediation", "(none provided)")
    confidence = vuln.get("confidence", "Unknown")
    category = vuln.get("category", "Unknown")
    data_flow = vuln.get("dataFlow", [])

    # Build data flow string if available
    data_flow_str = ""
    if data_flow:
        flow_lines = []
        for df in data_flow:
            flow_lines.append("  {} (line {}): {}".format(
                df.get("file", "?"), df.get("line", "?"), df.get("code", "?")))
        data_flow_str = "\nData Flow:\n" + "\n".join(flow_lines)

    prompt = """You are an expert security code reviewer. Analyze this vulnerability finding from a SAST (Static Application Security Testing) scanner.

Project: {project}
Language: {language}
File: {file_path}
Line: {line_number}
Scanner Confidence: {confidence}

Code Context:
```
{code_snippet}
```
{data_flow}

Vulnerability: {title}
Severity: {severity}
CWE: {cwe}
Category: {category}
Remediation: {remediation}

Based on the code context and vulnerability description, determine:

1. Is this a TRUE POSITIVE (real, exploitable vulnerability)?
2. Is this a FALSE POSITIVE (the code is actually safe, or the finding is incorrect)?
3. Are you UNCERTAIN (not enough context to determine)?

Consider:
- Does the code actually exhibit the described vulnerability?
- Is there sanitization/validation that the scanner may have missed?
- Is the vulnerability exploitable in practice?
- Could this be a test/example file intentionally containing vulnerable code?

Respond with ONLY a JSON object (no markdown, no extra text):
{{"verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "UNCERTAIN", "reason": "brief 1-2 sentence explanation", "confidence": 0.0 to 1.0}}""".format(
        project=project_name,
        language=language,
        file_path=file_path,
        line_number=line_number,
        confidence=confidence,
        code_snippet=code_snippet,
        data_flow=data_flow_str,
        title=title,
        severity=severity,
        cwe=cwe,
        category=category,
        remediation=remediation
    )
    return prompt


def call_claude(client, prompt, retry=0):
    """Send a verification prompt to Claude and parse the JSON response."""
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=300,
            temperature=0.0,
            messages=[{"role": "user", "content": prompt}]
        )
        text = response.content[0].text.strip()

        # Try to extract JSON from the response
        # Handle cases where Claude wraps in ```json ... ```
        if text.startswith("```"):
            # Strip markdown code fences
            lines = text.split("\n")
            json_lines = []
            in_block = False
            for line in lines:
                if line.startswith("```"):
                    in_block = not in_block
                    continue
                if in_block or not line.startswith("```"):
                    json_lines.append(line)
            text = "\n".join(json_lines).strip()

        # Find JSON object in text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]

        result = json.loads(text)

        # Validate
        verdict = result.get("verdict", "").upper()
        if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"):
            result["verdict"] = "UNCERTAIN"
            result["reason"] = result.get("reason", "Could not parse verdict")

        # Normalize confidence
        conf = result.get("confidence", 0.5)
        if isinstance(conf, str):
            try:
                conf = float(conf)
            except ValueError:
                conf = 0.5
        result["confidence"] = max(0.0, min(1.0, conf))

        return result

    except json.JSONDecodeError as e:
        if retry < MAX_RETRIES:
            time.sleep(RETRY_DELAY)
            return call_claude(client, prompt, retry + 1)
        return {"verdict": "UNCERTAIN", "reason": "Failed to parse AI response: " + str(e), "confidence": 0.0}

    except anthropic.RateLimitError:
        if retry < MAX_RETRIES:
            wait = RETRY_DELAY * (2 ** retry)
            print("    Rate limited, waiting {}s...".format(wait))
            time.sleep(wait)
            return call_claude(client, prompt, retry + 1)
        return {"verdict": "UNCERTAIN", "reason": "Rate limited after retries", "confidence": 0.0}

    except Exception as e:
        if retry < MAX_RETRIES:
            time.sleep(RETRY_DELAY)
            return call_claude(client, prompt, retry + 1)
        return {"verdict": "UNCERTAIN", "reason": "API error: " + str(e), "confidence": 0.0}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  SAST Finding AI Verification")
    print("  Model: {}".format(MODEL))
    print("  Timestamp: {}".format(datetime.now(timezone.utc).isoformat()))
    print("=" * 70)
    print()

    # Load scan results
    print("[1/4] Loading scan results from {}...".format(RESULTS_DIR))
    projects = load_scan_results()
    if not projects:
        print("ERROR: No scan results with vulnerabilities found!")
        sys.exit(1)

    total_vulns = sum(p.get("total_vulnerabilities", 0) for p in projects)
    print("  Found {} projects with {} total vulnerabilities".format(len(projects), total_vulns))
    for p in projects:
        print("    - {}: {} vulns ({})".format(
            p["project"], p["total_vulnerabilities"], p["language"]))
    print()

    # Sample vulnerabilities
    print("[2/4] Sampling vulnerabilities (max {} per project)...".format(MAX_VULNS_PER_PROJECT))
    all_samples = []
    for proj in projects:
        sampled = sample_vulnerabilities(proj)
        for v in sampled:
            all_samples.append({
                "project": proj["project"],
                "language": proj["language"],
                "scanner_port": proj.get("scanner_port", 0),
                "vulnerability": v
            })
        print("    - {}: sampled {}/{} vulnerabilities".format(
            proj["project"], len(sampled), proj["total_vulnerabilities"]))

    print("  Total to verify: {}".format(len(all_samples)))
    print()

    # Verify with Claude
    print("[3/4] Verifying with Claude AI...")
    client = anthropic.Anthropic(api_key=API_KEY)

    verdicts = []
    for i, sample in enumerate(all_samples):
        vuln = sample["vulnerability"]
        project = sample["project"]
        language = sample["language"]

        print("  [{}/{}] {} :: {} (line {}) [{}]".format(
            i + 1, len(all_samples),
            project,
            vuln.get("title", "?")[:60],
            vuln.get("lineNumber", "?"),
            vuln.get("severity", "?")
        ), end="", flush=True)

        prompt = build_verification_prompt(vuln, project, language)
        result = call_claude(client, prompt)

        verdict_record = {
            "project": project,
            "language": language,
            "scanner_port": sample["scanner_port"],
            "vuln_id": vuln.get("id", "unknown"),
            "vuln_title": vuln.get("title", "unknown"),
            "severity": vuln.get("severity", "unknown"),
            "cwe": vuln.get("cwe", "unknown"),
            "category": vuln.get("category", "unknown"),
            "file": vuln.get("filePath", "unknown"),
            "line": vuln.get("lineNumber", 0),
            "ai_verdict": result["verdict"],
            "ai_reason": result["reason"],
            "ai_confidence": result["confidence"]
        }
        verdicts.append(verdict_record)

        symbol = {"TRUE_POSITIVE": " -> TP", "FALSE_POSITIVE": " -> FP", "UNCERTAIN": " -> ??"}
        print(symbol.get(result["verdict"], " -> ??") + " (conf={:.0%})".format(result["confidence"]))

        # Small delay to avoid rate limiting
        time.sleep(0.5)

    print()

    # Compute summary statistics
    print("[4/4] Computing summary statistics...")

    total = len(verdicts)
    tp_count = sum(1 for v in verdicts if v["ai_verdict"] == "TRUE_POSITIVE")
    fp_count = sum(1 for v in verdicts if v["ai_verdict"] == "FALSE_POSITIVE")
    unc_count = sum(1 for v in verdicts if v["ai_verdict"] == "UNCERTAIN")

    tp_pct = (tp_count / total * 100) if total > 0 else 0
    fp_pct = (fp_count / total * 100) if total > 0 else 0
    unc_pct = (unc_count / total * 100) if total > 0 else 0

    avg_confidence = sum(v["ai_confidence"] for v in verdicts) / total if total > 0 else 0

    # Per-scanner (language) stats
    scanner_stats = defaultdict(lambda: {"total": 0, "tp": 0, "fp": 0, "uncertain": 0})
    for v in verdicts:
        lang = v["language"]
        scanner_stats[lang]["total"] += 1
        if v["ai_verdict"] == "TRUE_POSITIVE":
            scanner_stats[lang]["tp"] += 1
        elif v["ai_verdict"] == "FALSE_POSITIVE":
            scanner_stats[lang]["fp"] += 1
        else:
            scanner_stats[lang]["uncertain"] += 1

    scanner_summary = {}
    for lang, stats in sorted(scanner_stats.items()):
        fp_rate = (stats["fp"] / stats["total"] * 100) if stats["total"] > 0 else 0
        scanner_summary[lang] = {
            "total_verified": stats["total"],
            "true_positives": stats["tp"],
            "false_positives": stats["fp"],
            "uncertain": stats["uncertain"],
            "false_positive_rate_pct": round(fp_rate, 1)
        }

    # Per-category stats
    category_stats = defaultdict(lambda: {"total": 0, "tp": 0, "fp": 0, "uncertain": 0})
    for v in verdicts:
        cat = v["category"]
        category_stats[cat]["total"] += 1
        if v["ai_verdict"] == "TRUE_POSITIVE":
            category_stats[cat]["tp"] += 1
        elif v["ai_verdict"] == "FALSE_POSITIVE":
            category_stats[cat]["fp"] += 1
        else:
            category_stats[cat]["uncertain"] += 1

    category_summary = {}
    for cat, stats in sorted(category_stats.items()):
        fp_rate = (stats["fp"] / stats["total"] * 100) if stats["total"] > 0 else 0
        category_summary[cat] = {
            "total_verified": stats["total"],
            "true_positives": stats["tp"],
            "false_positives": stats["fp"],
            "uncertain": stats["uncertain"],
            "false_positive_rate_pct": round(fp_rate, 1)
        }

    # Per-project stats
    project_stats = defaultdict(lambda: {"total": 0, "tp": 0, "fp": 0, "uncertain": 0, "language": ""})
    for v in verdicts:
        proj = v["project"]
        project_stats[proj]["total"] += 1
        project_stats[proj]["language"] = v["language"]
        if v["ai_verdict"] == "TRUE_POSITIVE":
            project_stats[proj]["tp"] += 1
        elif v["ai_verdict"] == "FALSE_POSITIVE":
            project_stats[proj]["fp"] += 1
        else:
            project_stats[proj]["uncertain"] += 1

    project_summary = {}
    for proj, stats in sorted(project_stats.items()):
        fp_rate = (stats["fp"] / stats["total"] * 100) if stats["total"] > 0 else 0
        project_summary[proj] = {
            "language": stats["language"],
            "total_verified": stats["total"],
            "true_positives": stats["tp"],
            "false_positives": stats["fp"],
            "uncertain": stats["uncertain"],
            "false_positive_rate_pct": round(fp_rate, 1)
        }

    # Build final output
    output = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": MODEL,
            "max_vulns_per_project": MAX_VULNS_PER_PROJECT,
            "total_projects_scanned": len(projects),
            "total_vulns_in_scans": total_vulns,
            "total_vulns_verified": total
        },
        "overall_summary": {
            "total_findings_verified": total,
            "true_positives": {"count": tp_count, "percentage": round(tp_pct, 1)},
            "false_positives": {"count": fp_count, "percentage": round(fp_pct, 1)},
            "uncertain": {"count": unc_count, "percentage": round(unc_pct, 1)},
            "average_ai_confidence": round(avg_confidence, 3)
        },
        "per_scanner_false_positive_rate": scanner_summary,
        "per_category_false_positive_rate": category_summary,
        "per_project_summary": project_summary,
        "detailed_verdicts": verdicts
    }

    # Save
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print("  Results saved to {}".format(OUTPUT_FILE))
    print()

    # Print summary
    print("=" * 70)
    print("  VERIFICATION SUMMARY")
    print("=" * 70)
    print()
    print("  Total findings verified:  {}".format(total))
    print("  True Positives:           {} ({:.1f}%)".format(tp_count, tp_pct))
    print("  False Positives:          {} ({:.1f}%)".format(fp_count, fp_pct))
    print("  Uncertain:                {} ({:.1f}%)".format(unc_count, unc_pct))
    print("  Average AI Confidence:    {:.1f}%".format(avg_confidence * 100))
    print()
    print("  Per-Scanner False Positive Rates:")
    print("  " + "-" * 50)
    for lang, stats in sorted(scanner_summary.items()):
        print("    {:<15s}  {}/{} findings = {:.1f}% FP rate".format(
            lang,
            stats["false_positives"],
            stats["total_verified"],
            stats["false_positive_rate_pct"]))
    print()
    print("  Per-Category False Positive Rates:")
    print("  " + "-" * 50)
    for cat, stats in sorted(category_summary.items()):
        print("    {:<30s}  {}/{} = {:.1f}% FP".format(
            cat[:30],
            stats["false_positives"],
            stats["total_verified"],
            stats["false_positive_rate_pct"]))
    print()
    print("  Per-Project Breakdown:")
    print("  " + "-" * 50)
    for proj, stats in sorted(project_summary.items()):
        print("    {:<25s} ({:<10s}) TP:{} FP:{} UNC:{} -> {:.1f}% FP".format(
            proj[:25],
            stats["language"],
            stats["true_positives"],
            stats["false_positives"],
            stats["uncertain"],
            stats["false_positive_rate_pct"]))
    print()

    # Highlight notable false positives
    fps = [v for v in verdicts if v["ai_verdict"] == "FALSE_POSITIVE"]
    if fps:
        print("  Notable False Positives:")
        print("  " + "-" * 50)
        for fp in fps[:15]:
            print("    [{severity}] {title}".format(
                severity=fp["severity"],
                title=fp["vuln_title"][:65]
            ))
            print("      File: {}:{} | CWE: {}".format(fp["file"], fp["line"], fp["cwe"]))
            print("      Reason: {}".format(fp["ai_reason"][:100]))
            print()

    print("=" * 70)
    print("  Done! Full results: {}".format(OUTPUT_FILE))
    print("=" * 70)


if __name__ == "__main__":
    main()
