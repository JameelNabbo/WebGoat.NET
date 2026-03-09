#!/usr/bin/env python3
"""
IaC SAST Scanner - Comprehensive Infrastructure as Code Security Scanner
Handles: Dockerfiles, Terraform, Kubernetes YAML, Helm, CloudFormation,
         Ansible, docker-compose, XML configs, YAML configs, TOML, INI,
         nginx/apache configs.
Runs as FastAPI on port 9019.
"""

import re
import io
import os
import uuid
import json
import logging
import traceback
import configparser
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

import yaml
import toml
import hcl2
import xml.etree.ElementTree as ET

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("iac-scanner")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="IaC SAST Scanner", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: Optional[str] = None

class Vulnerability(BaseModel):
    id: str
    file: str
    line: int
    severity: str          # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    recommendation: str
    cwe: Optional[str] = None
    snippet: Optional[str] = None

class ScanResponse(BaseModel):
    scanId: str
    vulnerabilities: List[dict]
    summary: dict
    scanDuration: float

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
INFO = "Info"

# ---------------------------------------------------------------------------
# Helper: find line number of a pattern / substring in content
# ---------------------------------------------------------------------------
def find_line(content: str, pattern: str, start: int = 0) -> int:
    """Return 1-based line number where pattern first appears (case-insensitive)."""
    lines = content.split("\n")
    pat = pattern.lower()
    for i, line in enumerate(lines[start:], start=start):
        if pat in line.lower():
            return i + 1
    return 1

def find_line_regex(content: str, regex, start: int = 0) -> int:
    lines = content.split("\n")
    for i, line in enumerate(lines[start:], start=start):
        if regex.search(line):
            return i + 1
    return 1

def snippet_at(content: str, line_num: int, ctx: int = 1) -> str:
    """Return snippet around line_num (1-based)."""
    lines = content.split("\n")
    start = max(0, line_num - 1 - ctx)
    end = min(len(lines), line_num + ctx)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))

def make_vuln(file: str, line: int, severity: str, category: str,
              title: str, description: str, recommendation: str,
              content: str, cwe: str = None) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "file": file,
        "line": line,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "cwe": cwe or "",
        "snippet": snippet_at(content, line),
    }

# ---------------------------------------------------------------------------
# Sensitive patterns (shared across scanners)
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{4,}', re.I), "password"),
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{8,}', re.I), "API key"),
    (re.compile(r'(?:secret[_-]?key|secret)\s*[=:]\s*["\']?[A-Za-z0-9_\-/+=]{8,}', re.I), "secret key"),
    (re.compile(r'(?:access[_-]?key|aws_access_key_id)\s*[=:]\s*["\']?AK[A-Z0-9]{14,}', re.I), "AWS access key"),
    (re.compile(r'(?:token|auth[_-]?token|bearer)\s*[=:]\s*["\']?[A-Za-z0-9_\-\.]{10,}', re.I), "auth token"),
    (re.compile(r'(?:private[_-]?key)\s*[=:]\s*["\']?[A-Za-z0-9_\-/+=]{8,}', re.I), "private key"),
    (re.compile(r'(?:connection[_-]?string|connstr)\s*[=:]\s*["\']?.{10,}', re.I), "connection string"),
    (re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', re.I), "private key block"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}', re.I), "GitHub PAT"),
    (re.compile(r'sk-[A-Za-z0-9]{20,}', re.I), "OpenAI/Stripe key"),
]

SENSITIVE_FILES = [".env", ".git", "id_rsa", "id_dsa", "id_ecdsa",
                   ".pem", ".key", ".p12", ".pfx", "credentials",
                   ".htpasswd", "shadow", ".npmrc", ".pypirc",
                   "wallet", "keystore"]

# ===================================================================
#  DOCKERFILE SCANNER (20+ rules)
# ===================================================================
def scan_dockerfile(filepath: str, content: str) -> List[dict]:
    vulns = []
    lines = content.split("\n")
    cat = "Dockerfile"

    has_user = False
    has_healthcheck = False
    from_count = 0
    from_as_count = 0
    last_from_line = 0

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        ln = i + 1

        # Track FROM
        if re.match(r'^FROM\s', line, re.I):
            from_count += 1
            last_from_line = ln
            if re.search(r'\bAS\s+\w+', line, re.I):
                from_as_count += 1
            # Rule 2: latest tag
            if re.search(r':latest\b', line) or (not re.search(r'[:@]', line.split()[1]) if len(line.split()) > 1 else False):
                img = line.split()[1] if len(line.split()) > 1 else "unknown"
                if "@sha256:" not in img and ":" not in img:
                    vulns.append(make_vuln(filepath, ln, MEDIUM, cat,
                        "Base image without explicit tag",
                        f"Image '{img}' has no tag (defaults to 'latest'). "
                        "The latest tag is mutable and can change unexpectedly.",
                        "Pin the image to a specific version tag or SHA256 digest.",
                        content, "CWE-829"))
                elif ":latest" in img:
                    vulns.append(make_vuln(filepath, ln, MEDIUM, cat,
                        "Using 'latest' tag for base image",
                        f"Image '{img}' uses the 'latest' tag which is mutable.",
                        "Pin the image to a specific version tag or SHA256 digest.",
                        content, "CWE-829"))

            # Rule 11: deprecated images
            deprecated = ["ubuntu:14.04", "ubuntu:12.04", "debian:wheezy",
                          "debian:jessie", "centos:6", "centos:7",
                          "python:2", "python:2.7", "node:8", "node:10",
                          "ruby:2.5", "ruby:2.4", "php:5", "php:7.0",
                          "alpine:3.8", "alpine:3.9"]
            for dep in deprecated:
                if dep in line.lower():
                    vulns.append(make_vuln(filepath, ln, MEDIUM, cat,
                        "Using deprecated/EOL base image",
                        f"Image contains deprecated base image '{dep}'. "
                        "EOL images no longer receive security patches.",
                        "Upgrade to a currently supported base image version.",
                        content, "CWE-1104"))

        # Track USER
        if re.match(r'^USER\s', line, re.I):
            user_val = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if user_val and user_val != "root" and user_val != "0":
                has_user = True
            elif user_val in ("root", "0"):
                vulns.append(make_vuln(filepath, ln, HIGH, cat,
                    "Explicitly running as root user",
                    "USER directive is set to 'root'. Containers should run as non-root.",
                    "Create and switch to a non-root user: RUN useradd -r appuser && USER appuser",
                    content, "CWE-250"))

        # Track HEALTHCHECK
        if re.match(r'^HEALTHCHECK\s', line, re.I):
            has_healthcheck = True

        # Rule 3: EXPOSE
        if re.match(r'^EXPOSE\s', line, re.I):
            ports_str = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            for p in re.findall(r'\d+', ports_str):
                port = int(p)
                # Rule 8: privileged ports
                if port < 1024 and port not in (80, 443, 8080, 8443):
                    vulns.append(make_vuln(filepath, ln, LOW, cat,
                        f"Exposing privileged port {port}",
                        f"Port {port} is a privileged port (<1024). "
                        "Running on privileged ports requires root.",
                        "Use a non-privileged port (>=1024) and map externally.",
                        content, "CWE-250"))
                if port in (22, 23, 3389, 5900):
                    vulns.append(make_vuln(filepath, ln, HIGH, cat,
                        f"Exposing remote access port {port}",
                        f"Port {port} is a remote access port (SSH/Telnet/RDP/VNC). "
                        "These should not be exposed in containers.",
                        "Remove this EXPOSE directive. Use docker exec for access.",
                        content, "CWE-284"))

        # Rule 4: COPY/ADD with wildcard
        if re.match(r'^(COPY|ADD)\s', line, re.I):
            parts = line.split()
            for part in parts[1:-1]:
                if "*" in part or "." == part:
                    vulns.append(make_vuln(filepath, ln, MEDIUM, cat,
                        "COPY/ADD with wildcard pattern",
                        f"Using wildcard '{part}' may copy sensitive files "
                        "(.env, .git, credentials) into the image.",
                        "Use explicit file paths or add a .dockerignore file.",
                        content, "CWE-200"))

            # Rule 13: Sensitive file copy
            for part in parts[1:-1]:
                for sf in SENSITIVE_FILES:
                    if sf in part.lower():
                        vulns.append(make_vuln(filepath, ln, HIGH, cat,
                            f"Copying potentially sensitive file: {part}",
                            f"Copying '{part}' may include sensitive data in the image.",
                            "Exclude sensitive files via .dockerignore or use secrets management.",
                            content, "CWE-200"))

        # Rule 5: Hardcoded secrets in ENV/ARG
        if re.match(r'^(ENV|ARG)\s', line, re.I):
            for pat, kind in SECRET_PATTERNS[:6]:
                if pat.search(line):
                    vulns.append(make_vuln(filepath, ln, CRITICAL, cat,
                        f"Hardcoded {kind} in {line.split()[0]}",
                        f"Sensitive value ({kind}) is hardcoded in the Dockerfile. "
                        "This is baked into the image and visible to anyone with access.",
                        "Use build arguments with --build-arg, Docker secrets, or environment files.",
                        content, "CWE-798"))
                    break

        # Rule 6: ADD instead of COPY
        if re.match(r'^ADD\s', line, re.I):
            args = line.split()
            src = args[1] if len(args) > 1 else ""
            if not src.startswith("http") and not src.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2")):
                vulns.append(make_vuln(filepath, ln, LOW, cat,
                    "Using ADD instead of COPY for local files",
                    "ADD has implicit tar extraction and URL fetch. "
                    "For simple file copies, COPY is more transparent and secure.",
                    "Use COPY instead of ADD unless tar extraction is needed.",
                    content, "CWE-706"))

        # Rule 9: curl/wget piped to shell
        if re.match(r'^RUN\s', line, re.I):
            if re.search(r'(curl|wget)\s.*\|\s*(sh|bash|zsh|dash)', line, re.I):
                vulns.append(make_vuln(filepath, ln, HIGH, cat,
                    "Piping download directly to shell",
                    "Downloading and executing scripts directly is dangerous. "
                    "A compromised server could serve malicious code.",
                    "Download the script first, verify its checksum, then execute.",
                    content, "CWE-829"))

            # Rule 10: Missing apt-get clean
            if re.search(r'apt-get\s+install', line, re.I):
                # Check if this RUN block includes cleanup
                run_block = line
                j = i
                while run_block.endswith("\\") and j + 1 < len(lines):
                    j += 1
                    run_block += " " + lines[j].strip()
                if not re.search(r'(apt-get\s+clean|rm\s+-rf\s+/var/lib/apt/lists)', run_block, re.I):
                    vulns.append(make_vuln(filepath, ln, LOW, cat,
                        "Missing apt-get clean after install",
                        "Package manager cache not cleaned after install, increasing image size.",
                        "Add '&& apt-get clean && rm -rf /var/lib/apt/lists/*' after install.",
                        content, "CWE-459"))

            if re.search(r'yum\s+install', line, re.I):
                run_block = line
                j = i
                while run_block.endswith("\\") and j + 1 < len(lines):
                    j += 1
                    run_block += " " + lines[j].strip()
                if not re.search(r'yum\s+clean', run_block, re.I):
                    vulns.append(make_vuln(filepath, ln, LOW, cat,
                        "Missing yum clean after install",
                        "Package manager cache not cleaned after install.",
                        "Add '&& yum clean all' after yum install.",
                        content, "CWE-459"))

            # Rule: running chmod 777
            if re.search(r'chmod\s+777', line):
                vulns.append(make_vuln(filepath, ln, HIGH, cat,
                    "Setting overly permissive file permissions (777)",
                    "chmod 777 grants read/write/execute to all users, "
                    "violating the principle of least privilege.",
                    "Use more restrictive permissions (e.g., 755 or 644).",
                    content, "CWE-732"))

            # Rule: disabling SSL verification
            if re.search(r'(--no-check-certificate|--insecure|-k\b|NODE_TLS_REJECT_UNAUTHORIZED=0|SSL_CERT_DIR=/dev/null)', line, re.I):
                vulns.append(make_vuln(filepath, ln, HIGH, cat,
                    "Disabling SSL/TLS certificate verification",
                    "SSL verification is being disabled, allowing man-in-the-middle attacks.",
                    "Use proper SSL certificates instead of disabling verification.",
                    content, "CWE-295"))

        # Rule 12: WORKDIR not absolute
        if re.match(r'^WORKDIR\s', line, re.I):
            wd = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if wd and not wd.startswith("/") and not wd.startswith("$"):
                vulns.append(make_vuln(filepath, ln, LOW, cat,
                    "WORKDIR is not an absolute path",
                    f"WORKDIR '{wd}' is relative. This can cause unexpected behavior.",
                    "Use an absolute path for WORKDIR (e.g., /app).",
                    content, "CWE-426"))

    # Rule 1: No USER directive at all
    if not has_user and from_count > 0:
        vulns.append(make_vuln(filepath, last_from_line, HIGH, cat,
            "Container running as root (no USER directive)",
            "No USER directive found. Container will run as root by default, "
            "which increases the impact of any container breakout.",
            "Add a USER directive to run as a non-root user.",
            content, "CWE-250"))

    # Rule 7: No HEALTHCHECK
    if not has_healthcheck and from_count > 0:
        vulns.append(make_vuln(filepath, 1, LOW, cat,
            "No HEALTHCHECK defined",
            "No HEALTHCHECK instruction found. Docker cannot determine "
            "if the container is healthy without it.",
            "Add a HEALTHCHECK instruction to monitor container health.",
            content, "CWE-703"))

    # Rule 14: Multiple FROM without --from
    if from_count > 1 and from_as_count == 0:
        vulns.append(make_vuln(filepath, 1, MEDIUM, cat,
            "Multiple FROM stages without named builds",
            f"Found {from_count} FROM instructions but none use AS for naming. "
            "This may create unintended layers in the final image.",
            "Use multi-stage builds: FROM image AS builder ... FROM image ... COPY --from=builder",
            content, "CWE-400"))

    return vulns


# ===================================================================
#  TERRAFORM SCANNER (30+ rules)
# ===================================================================
def scan_terraform(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "Terraform"

    # Try to parse HCL
    parsed = None
    try:
        parsed = hcl2.loads(content)
    except Exception:
        logger.warning(f"Could not parse HCL in {filepath}, falling back to regex")

    # If HCL parsing succeeded, do deep inspection
    if parsed:
        vulns.extend(_scan_tf_parsed(filepath, content, parsed))

    # Always do regex-based scanning for things HCL parser might miss
    vulns.extend(_scan_tf_regex(filepath, content))

    return vulns

def _scan_tf_parsed(filepath: str, content: str, parsed: dict) -> List[dict]:
    vulns = []
    cat = "Terraform"

    resources = parsed.get("resource", [])
    if not isinstance(resources, list):
        resources = [resources]

    for resource_block in resources:
        if not isinstance(resource_block, dict):
            continue
        for res_type, res_instances in resource_block.items():
            if not isinstance(res_instances, dict):
                continue
            for res_name, res_config in res_instances.items():
                if isinstance(res_config, list):
                    res_config = res_config[0] if res_config else {}
                if not isinstance(res_config, dict):
                    continue

                # --- S3 Bucket Rules ---
                if res_type == "aws_s3_bucket":
                    # Rule 1: Public ACL
                    acl = res_config.get("acl", "")
                    if acl in ("public-read", "public-read-write"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, acl), CRITICAL, cat,
                            f"S3 bucket '{res_name}' has public ACL",
                            f"Bucket ACL is set to '{acl}', making it publicly accessible.",
                            "Set ACL to 'private' and use bucket policies for access control.",
                            content, "CWE-284"))

                # Rule: S3 bucket without versioning
                if res_type == "aws_s3_bucket_versioning":
                    vc = res_config.get("versioning_configuration", {})
                    if isinstance(vc, list):
                        vc = vc[0] if vc else {}
                    if isinstance(vc, dict) and vc.get("status") == "Disabled":
                        vulns.append(make_vuln(filepath,
                            find_line(content, "Disabled"), MEDIUM, cat,
                            f"S3 bucket versioning disabled for '{res_name}'",
                            "Versioning is disabled, preventing recovery from accidental deletions.",
                            "Enable versioning for data protection.",
                            content, "CWE-693"))

                # --- Security Group Rules ---
                if res_type == "aws_security_group":
                    ingress_list = res_config.get("ingress", [])
                    if isinstance(ingress_list, dict):
                        ingress_list = [ingress_list]
                    for ingress in ingress_list:
                        if not isinstance(ingress, dict):
                            continue
                        cidrs = ingress.get("cidr_blocks", [])
                        if isinstance(cidrs, str):
                            cidrs = [cidrs]
                        from_port = ingress.get("from_port", 0)
                        to_port = ingress.get("to_port", 0)

                        # Rule 2: 0.0.0.0/0 ingress
                        if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
                            vulns.append(make_vuln(filepath,
                                find_line(content, "0.0.0.0/0"), HIGH, cat,
                                f"Security group '{res_name}' allows ingress from 0.0.0.0/0",
                                "Unrestricted ingress allows traffic from the entire internet.",
                                "Restrict CIDR blocks to known IP ranges.",
                                content, "CWE-284"))

                            # Rule 6: SSH open to world
                            if from_port == 22 or to_port == 22 or (isinstance(from_port, int) and isinstance(to_port, int) and from_port <= 22 <= to_port):
                                vulns.append(make_vuln(filepath,
                                    find_line(content, "22"), CRITICAL, cat,
                                    f"SSH port 22 open to the world in '{res_name}'",
                                    "SSH is accessible from any IP, a major attack vector.",
                                    "Restrict SSH to specific IP addresses or use a bastion host.",
                                    content, "CWE-284"))

                            if from_port == 3389 or to_port == 3389:
                                vulns.append(make_vuln(filepath,
                                    find_line(content, "3389"), CRITICAL, cat,
                                    f"RDP port 3389 open to the world in '{res_name}'",
                                    "RDP is accessible from any IP.",
                                    "Restrict RDP to specific IP addresses or use a VPN.",
                                    content, "CWE-284"))

                # --- RDS Rules ---
                if res_type == "aws_db_instance":
                    # Rule 11: publicly accessible
                    if res_config.get("publicly_accessible") in (True, "true"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, "publicly_accessible"), CRITICAL, cat,
                            f"RDS instance '{res_name}' is publicly accessible",
                            "Database is directly accessible from the internet.",
                            "Set publicly_accessible = false and access via VPC.",
                            content, "CWE-284"))
                    # Rule 3: unencrypted
                    if not res_config.get("storage_encrypted", False):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"RDS instance '{res_name}' storage not encrypted",
                            "Database storage is not encrypted at rest.",
                            "Set storage_encrypted = true.",
                            content, "CWE-311"))
                    # Rule 17: no backup retention
                    ret = res_config.get("backup_retention_period", None)
                    if ret is not None and (ret == 0 or ret == "0"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, "backup_retention"), MEDIUM, cat,
                            f"RDS '{res_name}' has no backup retention",
                            "Backup retention is disabled. Data loss risk.",
                            "Set backup_retention_period to at least 7 days.",
                            content, "CWE-693"))

                # --- EBS Volume ---
                if res_type == "aws_ebs_volume":
                    if not res_config.get("encrypted", False):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"EBS volume '{res_name}' not encrypted",
                            "EBS volume data is not encrypted at rest.",
                            "Set encrypted = true.",
                            content, "CWE-311"))

                # --- IAM Policy ---
                if res_type == "aws_iam_policy" or res_type == "aws_iam_role_policy":
                    policy_str = json.dumps(res_config) if isinstance(res_config, dict) else str(res_config)
                    if '"*"' in policy_str and '"Allow"' in policy_str:
                        vulns.append(make_vuln(filepath,
                            find_line(content, '"*"'), CRITICAL, cat,
                            f"IAM policy '{res_name}' uses wildcard (*) permissions",
                            "Policy grants access to all resources/actions, violating least privilege.",
                            "Restrict to specific resources and actions.",
                            content, "CWE-250"))

                # --- Lambda ---
                if res_type == "aws_lambda_function":
                    if not res_config.get("vpc_config"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"Lambda '{res_name}' not deployed in VPC",
                            "Lambda function runs outside VPC, cannot access private resources securely.",
                            "Add vpc_config with subnet_ids and security_group_ids.",
                            content, "CWE-284"))

                # --- CloudFront ---
                if res_type == "aws_cloudfront_distribution":
                    if not res_config.get("web_acl_id"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"CloudFront '{res_name}' without WAF",
                            "CloudFront distribution has no WAF attached.",
                            "Associate a WAF web ACL with the CloudFront distribution.",
                            content, "CWE-693"))

                # --- ELB / ALB ---
                if res_type in ("aws_lb", "aws_alb", "aws_elb"):
                    cfg_str = json.dumps(res_config)
                    if "443" not in cfg_str and "HTTPS" not in cfg_str.upper():
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"Load balancer '{res_name}' may lack HTTPS listener",
                            "No HTTPS/443 configuration detected on load balancer.",
                            "Add an HTTPS listener with a valid SSL certificate.",
                            content, "CWE-319"))

                # --- KMS Key ---
                if res_type == "aws_kms_key":
                    if not res_config.get("enable_key_rotation", False):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"KMS key '{res_name}' rotation not enabled",
                            "Automatic key rotation is not enabled.",
                            "Set enable_key_rotation = true.",
                            content, "CWE-320"))

                # --- SNS ---
                if res_type == "aws_sns_topic":
                    if not res_config.get("kms_master_key_id"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"SNS topic '{res_name}' not encrypted",
                            "SNS topic messages are not encrypted at rest.",
                            "Add kms_master_key_id for encryption.",
                            content, "CWE-311"))

                # --- SQS ---
                if res_type == "aws_sqs_queue":
                    if not res_config.get("kms_master_key_id"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), MEDIUM, cat,
                            f"SQS queue '{res_name}' not encrypted",
                            "SQS queue messages are not encrypted at rest.",
                            "Add kms_master_key_id for encryption.",
                            content, "CWE-311"))

                # --- Missing tags ---
                if res_type.startswith("aws_") and res_type not in (
                    "aws_iam_policy", "aws_iam_role_policy", "aws_iam_policy_document",
                    "aws_iam_role", "aws_security_group_rule"):
                    if not res_config.get("tags"):
                        vulns.append(make_vuln(filepath,
                            find_line(content, res_name), LOW, cat,
                            f"Resource '{res_type}.{res_name}' missing tags",
                            "No tags defined. Tags are needed for cost tracking and compliance.",
                            "Add tags for environment, owner, project, etc.",
                            content, "CWE-1078"))

    return vulns

def _scan_tf_regex(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "Terraform"
    lines = content.split("\n")

    # Rule 9: Hardcoded credentials in provider or variables
    for i, line in enumerate(lines):
        ln = i + 1
        stripped = line.strip()

        for pat, kind in SECRET_PATTERNS[:6]:
            if pat.search(stripped):
                # Skip if it's a variable reference
                if re.search(r'var\.\w+|local\.\w+|data\.\w+', stripped):
                    continue
                vulns.append(make_vuln(filepath, ln, CRITICAL, cat,
                    f"Hardcoded {kind} in Terraform file",
                    f"Sensitive value ({kind}) appears to be hardcoded.",
                    "Use variables with sensitive = true, or use a secrets manager.",
                    content, "CWE-798"))
                break

    # Rule 5: Missing CloudTrail
    if "aws_cloudtrail" not in content and "aws_" in content:
        if "aws_instance" in content or "aws_s3_bucket" in content:
            vulns.append(make_vuln(filepath, 1, MEDIUM, cat,
                "No CloudTrail logging configured",
                "No aws_cloudtrail resource found. API activity may not be logged.",
                "Add an aws_cloudtrail resource to log all API calls.",
                content, "CWE-778"))

    # Rule 7: Default VPC
    if "aws_default_vpc" in content or "default = true" in content:
        ln = find_line(content, "default_vpc") or find_line(content, "default = true")
        vulns.append(make_vuln(filepath, ln, MEDIUM, cat,
            "Using default VPC",
            "Default VPCs have permissive security configurations.",
            "Create a custom VPC with proper network segmentation.",
            content, "CWE-1188"))

    # Rule 20: Missing access logging on S3
    if "aws_s3_bucket" in content and "logging" not in content and "aws_s3_bucket_logging" not in content:
        vulns.append(make_vuln(filepath, find_line(content, "aws_s3_bucket"), LOW, cat,
            "S3 bucket without access logging",
            "No access logging configured for S3 bucket.",
            "Enable access logging to track bucket access.",
            content, "CWE-778"))

    # Rule: No VPC flow logs
    if "aws_vpc" in content and "aws_flow_log" not in content:
        vulns.append(make_vuln(filepath, find_line(content, "aws_vpc"), MEDIUM, cat,
            "No VPC flow logs configured",
            "VPC flow logs are not enabled. Network traffic is not being monitored.",
            "Add aws_flow_log resource to capture VPC traffic.",
            content, "CWE-778"))

    # Rule 10: No MFA delete on S3
    if "aws_s3_bucket" in content and "mfa_delete" not in content:
        vulns.append(make_vuln(filepath, find_line(content, "aws_s3_bucket"), LOW, cat,
            "S3 bucket without MFA delete protection",
            "MFA delete is not enabled, allowing accidental/malicious deletion.",
            "Enable mfa_delete in the versioning configuration.",
            content, "CWE-693"))

    return vulns


# ===================================================================
#  KUBERNETES YAML SCANNER (25+ rules)
# ===================================================================
def scan_kubernetes(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "Kubernetes"

    try:
        docs = list(yaml.safe_load_all(content))
    except Exception as e:
        logger.warning(f"Could not parse YAML {filepath}: {e}")
        return vulns

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "")

        # Rule 8: default namespace
        if namespace == "default" or (not namespace and kind in (
            "Deployment", "StatefulSet", "DaemonSet", "Pod", "Service",
            "ReplicaSet", "Job", "CronJob")):
            vulns.append(make_vuln(filepath,
                find_line(content, f"name: {name}") if name != "unknown" else 1,
                LOW, cat,
                f"{kind} '{name}' uses default namespace",
                "Using the default namespace can lead to resource conflicts and lacks isolation.",
                "Deploy resources in a dedicated namespace.",
                content, "CWE-1188"))

        # Get pod spec
        spec = doc.get("spec", {}) or {}
        pod_spec = None
        if kind == "Pod":
            pod_spec = spec
        elif kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            template = spec.get("template", {}) or {}
            pod_spec = template.get("spec", {}) or {}
        elif kind == "CronJob":
            job_template = spec.get("jobTemplate", {}) or {}
            job_spec = job_template.get("spec", {}) or {}
            template = job_spec.get("template", {}) or {}
            pod_spec = template.get("spec", {}) or {}

        if pod_spec:
            # Rule 4: hostNetwork
            if pod_spec.get("hostNetwork"):
                vulns.append(make_vuln(filepath,
                    find_line(content, "hostNetwork"), HIGH, cat,
                    f"{kind} '{name}' uses hostNetwork",
                    "hostNetwork shares the host's network namespace, bypassing network isolation.",
                    "Remove hostNetwork: true unless absolutely necessary.",
                    content, "CWE-284"))

            # Rule 4: hostPID
            if pod_spec.get("hostPID"):
                vulns.append(make_vuln(filepath,
                    find_line(content, "hostPID"), HIGH, cat,
                    f"{kind} '{name}' uses hostPID",
                    "hostPID allows seeing all processes on the host.",
                    "Remove hostPID: true.",
                    content, "CWE-284"))

            # Rule 4: hostIPC
            if pod_spec.get("hostIPC"):
                vulns.append(make_vuln(filepath,
                    find_line(content, "hostIPC"), HIGH, cat,
                    f"{kind} '{name}' uses hostIPC",
                    "hostIPC shares the host's IPC namespace.",
                    "Remove hostIPC: true.",
                    content, "CWE-284"))

            containers = pod_spec.get("containers", []) or []
            init_containers = pod_spec.get("initContainers", []) or []
            all_containers = containers + init_containers

            for container in all_containers:
                if not isinstance(container, dict):
                    continue
                cname = container.get("name", "unknown")
                image = container.get("image", "")

                # Rule 16: image without tag
                if image and ":" not in image and "@" not in image:
                    vulns.append(make_vuln(filepath,
                        find_line(content, f"image: {image}") or find_line(content, image),
                        MEDIUM, cat,
                        f"Container '{cname}' image without tag",
                        f"Image '{image}' has no tag, defaults to 'latest'.",
                        "Pin to a specific image tag or SHA256 digest.",
                        content, "CWE-829"))
                elif image and ":latest" in image:
                    vulns.append(make_vuln(filepath,
                        find_line(content, image), MEDIUM, cat,
                        f"Container '{cname}' uses 'latest' tag",
                        f"Image '{image}' uses mutable 'latest' tag.",
                        "Pin to a specific version tag.",
                        content, "CWE-829"))

                sec_ctx = container.get("securityContext", {}) or {}

                # Rule 1: privileged
                if sec_ctx.get("privileged"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, "privileged: true") or find_line(content, "privileged"),
                        CRITICAL, cat,
                        f"Container '{cname}' runs in privileged mode",
                        "Privileged containers have full access to the host.",
                        "Remove privileged: true and use specific capabilities.",
                        content, "CWE-250"))

                # Rule 1: runAsRoot
                run_as_user = sec_ctx.get("runAsUser")
                run_as_non_root = sec_ctx.get("runAsNonRoot")
                if run_as_user == 0:
                    vulns.append(make_vuln(filepath,
                        find_line(content, "runAsUser: 0") or find_line(content, "runAsUser"),
                        HIGH, cat,
                        f"Container '{cname}' runs as root (UID 0)",
                        "Container is explicitly set to run as root.",
                        "Set runAsNonRoot: true and runAsUser to a non-zero UID.",
                        content, "CWE-250"))
                if run_as_non_root is False:
                    vulns.append(make_vuln(filepath,
                        find_line(content, "runAsNonRoot: false") or find_line(content, "runAsNonRoot"),
                        HIGH, cat,
                        f"Container '{cname}' allows running as root",
                        "runAsNonRoot is explicitly set to false.",
                        "Set runAsNonRoot: true.",
                        content, "CWE-250"))

                # Rule 5: writable root filesystem
                if not sec_ctx.get("readOnlyRootFilesystem"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, f"name: {cname}") or 1,
                        MEDIUM, cat,
                        f"Container '{cname}' has writable root filesystem",
                        "Root filesystem is writable, allowing attackers to modify binaries.",
                        "Set readOnlyRootFilesystem: true.",
                        content, "CWE-732"))

                # Rule 11: allowPrivilegeEscalation
                if sec_ctx.get("allowPrivilegeEscalation") is True or (
                    sec_ctx.get("allowPrivilegeEscalation") is None and not sec_ctx.get("privileged")):
                    # Only flag if explicitly true or not set
                    if sec_ctx.get("allowPrivilegeEscalation") is True:
                        vulns.append(make_vuln(filepath,
                            find_line(content, "allowPrivilegeEscalation"),
                            HIGH, cat,
                            f"Container '{cname}' allows privilege escalation",
                            "allowPrivilegeEscalation is true, container processes can gain more privileges.",
                            "Set allowPrivilegeEscalation: false.",
                            content, "CWE-250"))

                # Rule 10: missing securityContext
                if not sec_ctx:
                    vulns.append(make_vuln(filepath,
                        find_line(content, f"name: {cname}") or 1,
                        MEDIUM, cat,
                        f"Container '{cname}' missing securityContext",
                        "No securityContext defined. Pod runs with default (often permissive) settings.",
                        "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, etc.",
                        content, "CWE-250"))

                # Rule 2: no resource limits
                resources = container.get("resources", {}) or {}
                if not resources.get("limits"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, f"name: {cname}") or 1,
                        MEDIUM, cat,
                        f"Container '{cname}' has no resource limits",
                        "No CPU/memory limits. Container can consume unlimited host resources.",
                        "Add resources.limits with cpu and memory.",
                        content, "CWE-770"))
                if not resources.get("requests"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, f"name: {cname}") or 1,
                        LOW, cat,
                        f"Container '{cname}' has no resource requests",
                        "No resource requests defined. Scheduler cannot make optimal placement decisions.",
                        "Add resources.requests with cpu and memory.",
                        content, "CWE-770"))

                # Rule 6: no probes
                if not container.get("readinessProbe"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, f"name: {cname}") or 1,
                        LOW, cat,
                        f"Container '{cname}' has no readinessProbe",
                        "No readiness probe. Traffic may be sent to unready pods.",
                        "Add a readinessProbe to check application health.",
                        content, "CWE-703"))
                if not container.get("livenessProbe"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, f"name: {cname}") or 1,
                        LOW, cat,
                        f"Container '{cname}' has no livenessProbe",
                        "No liveness probe. Crashed containers may not be restarted.",
                        "Add a livenessProbe to enable automatic recovery.",
                        content, "CWE-703"))

                # Rule 9: secrets in env vars
                env_list = container.get("env", []) or []
                for env_var in env_list:
                    if not isinstance(env_var, dict):
                        continue
                    env_name = (env_var.get("name", "") or "").lower()
                    env_value = env_var.get("value", "")
                    if env_value and any(kw in env_name for kw in
                        ["password", "secret", "key", "token", "api_key", "apikey",
                         "credential", "private"]):
                        vulns.append(make_vuln(filepath,
                            find_line(content, env_var.get("name", "")),
                            HIGH, cat,
                            f"Secret '{env_var.get('name')}' hardcoded in env",
                            "Sensitive value is hardcoded in the manifest. "
                            "Anyone with kubectl access can read it.",
                            "Use Kubernetes Secrets with valueFrom.secretKeyRef.",
                            content, "CWE-798"))

                # Rule: capabilities
                caps = sec_ctx.get("capabilities", {}) or {}
                add_caps = caps.get("add", []) or []
                dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE",
                                  "NET_RAW", "SYS_MODULE", "DAC_OVERRIDE"]
                for cap in add_caps:
                    if cap in dangerous_caps:
                        vulns.append(make_vuln(filepath,
                            find_line(content, cap), HIGH, cat,
                            f"Container '{cname}' adds dangerous capability: {cap}",
                            f"Adding {cap} capability grants elevated privileges.",
                            "Remove unnecessary capabilities. Use drop: [ALL] and add only what's needed.",
                            content, "CWE-250"))

            # Rule 17: emptyDir for sensitive data (heuristic)
            volumes = pod_spec.get("volumes", []) or []
            for vol in volumes:
                if not isinstance(vol, dict):
                    continue
                vol_name = vol.get("name", "").lower()
                if vol.get("emptyDir") is not None:
                    if any(kw in vol_name for kw in ["secret", "key", "cert", "tls", "credential", "token"]):
                        vulns.append(make_vuln(filepath,
                            find_line(content, vol.get("name", "")),
                            MEDIUM, cat,
                            f"emptyDir volume '{vol.get('name')}' for sensitive data",
                            "emptyDir volumes are not encrypted and are lost on pod restart.",
                            "Use Kubernetes Secrets or PersistentVolumes for sensitive data.",
                            content, "CWE-311"))

        # Rule 13: exposed dashboard
        if kind == "Service":
            svc_spec = spec
            selector = svc_spec.get("selector", {}) or {}
            if any("dashboard" in str(v).lower() for v in selector.values()):
                svc_type = svc_spec.get("type", "ClusterIP")
                if svc_type in ("NodePort", "LoadBalancer"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, "dashboard"),
                        HIGH, cat,
                        f"Kubernetes dashboard exposed via {svc_type}",
                        "Dashboard is exposed externally, providing cluster management access.",
                        "Use kubectl proxy or restrict with network policies.",
                        content, "CWE-284"))

        # Rule 14: Tiller (Helm 2) deployment
        if kind == "Deployment":
            dep_str = json.dumps(doc)
            if "tiller" in dep_str.lower():
                vulns.append(make_vuln(filepath,
                    find_line(content, "tiller"),
                    HIGH, cat,
                    "Tiller (Helm 2) deployment detected",
                    "Helm 2's Tiller has cluster-admin privileges and is a security risk.",
                    "Upgrade to Helm 3, which eliminates Tiller.",
                    content, "CWE-250"))

        # Rule 19: LoadBalancer without annotations
        if kind == "Service" and spec.get("type") == "LoadBalancer":
            annotations = metadata.get("annotations", {}) or {}
            if not annotations:
                vulns.append(make_vuln(filepath,
                    find_line(content, "LoadBalancer"),
                    LOW, cat,
                    f"Service '{name}' is LoadBalancer without annotations",
                    "LoadBalancer service without cloud-specific annotations may have unintended configuration.",
                    "Add appropriate cloud provider annotations for security and configuration.",
                    content, "CWE-1188"))

        # Rule 15: RBAC - ClusterRoleBinding with cluster-admin
        if kind == "ClusterRoleBinding":
            role_ref = doc.get("roleRef", {}) or {}
            if role_ref.get("name") == "cluster-admin":
                subjects = doc.get("subjects", []) or []
                for subj in subjects:
                    if isinstance(subj, dict):
                        vulns.append(make_vuln(filepath,
                            find_line(content, "cluster-admin"),
                            CRITICAL, cat,
                            f"ClusterRoleBinding '{name}' grants cluster-admin",
                            f"Subject '{subj.get('name', 'unknown')}' has cluster-admin role, "
                            "granting full cluster access.",
                            "Use more restrictive roles following least privilege principle.",
                            content, "CWE-250"))

        # Rule: RBAC ClusterRole with wildcards
        if kind == "ClusterRole" or kind == "Role":
            rules_list = doc.get("rules", []) or []
            for rule in rules_list:
                if not isinstance(rule, dict):
                    continue
                verbs = rule.get("verbs", [])
                resources_list = rule.get("resources", [])
                if "*" in verbs or "*" in resources_list:
                    vulns.append(make_vuln(filepath,
                        find_line(content, '"*"') or find_line(content, "'*'") or find_line(content, "- '*'"),
                        HIGH, cat,
                        f"{kind} '{name}' uses wildcard permissions",
                        "Wildcard verbs or resources grant overly broad access.",
                        "Specify exact verbs and resources needed.",
                        content, "CWE-250"))

    return vulns


# ===================================================================
#  DOCKER COMPOSE SCANNER (10+ rules)
# ===================================================================
def scan_docker_compose(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "Docker Compose"

    try:
        doc = yaml.safe_load(content)
    except Exception as e:
        logger.warning(f"Could not parse docker-compose {filepath}: {e}")
        return vulns

    if not isinstance(doc, dict):
        return vulns

    services = doc.get("services", {}) or {}
    for svc_name, svc_config in services.items():
        if not isinstance(svc_config, dict):
            continue

        # Rule 1: privileged mode
        if svc_config.get("privileged"):
            vulns.append(make_vuln(filepath,
                find_line(content, "privileged"), CRITICAL, cat,
                f"Service '{svc_name}' runs in privileged mode",
                "Privileged containers have full access to the host system.",
                "Remove privileged: true and use specific capabilities.",
                content, "CWE-250"))

        # Rule 2: host network mode
        if svc_config.get("network_mode") == "host":
            vulns.append(make_vuln(filepath,
                find_line(content, "network_mode"), HIGH, cat,
                f"Service '{svc_name}' uses host network",
                "Host networking bypasses Docker's network isolation.",
                "Use bridge networking or custom networks.",
                content, "CWE-284"))

        # Rule 3: Exposed ports
        ports = svc_config.get("ports", [])
        for port_mapping in ports:
            port_str = str(port_mapping)
            # Check if binding to 0.0.0.0
            if ":" in port_str:
                host_part = port_str.split(":")[0]
                if host_part and not host_part.startswith("127."):
                    # Check for sensitive ports
                    for p in re.findall(r'\d+', port_str):
                        if int(p) in (22, 23, 3389, 5900, 3306, 5432, 6379, 27017, 9200):
                            vulns.append(make_vuln(filepath,
                                find_line(content, port_str),
                                HIGH, cat,
                                f"Service '{svc_name}' exposes sensitive port {p}",
                                f"Database/admin port {p} is exposed to the host.",
                                "Bind to 127.0.0.1 or use internal Docker networking.",
                                content, "CWE-284"))

        # Rule 4: environment secrets
        env = svc_config.get("environment", {})
        if isinstance(env, dict):
            env_items = env.items()
        elif isinstance(env, list):
            env_items = []
            for item in env:
                if "=" in str(item):
                    k, v = str(item).split("=", 1)
                    env_items.append((k, v))
        else:
            env_items = []

        for env_key, env_val in env_items:
            env_key_lower = env_key.lower()
            if any(kw in env_key_lower for kw in
                   ["password", "secret", "key", "token", "api_key",
                    "credential", "private_key"]):
                if env_val and not str(env_val).startswith("${"):
                    vulns.append(make_vuln(filepath,
                        find_line(content, env_key),
                        HIGH, cat,
                        f"Service '{svc_name}' has hardcoded secret: {env_key}",
                        f"Sensitive env var '{env_key}' has a hardcoded value.",
                        "Use Docker secrets, .env files (not committed), or external secret management.",
                        content, "CWE-798"))

        # Rule 5: no resource limits
        if not svc_config.get("deploy", {}).get("resources") and not svc_config.get("mem_limit") and not svc_config.get("cpus"):
            vulns.append(make_vuln(filepath,
                find_line(content, f"{svc_name}:") or 1,
                LOW, cat,
                f"Service '{svc_name}' has no resource limits",
                "No CPU/memory limits. Container can consume unlimited resources.",
                "Add deploy.resources.limits or mem_limit/cpus.",
                content, "CWE-770"))

        # Rule 6: latest tag
        image = svc_config.get("image", "")
        if image:
            if ":latest" in image or (":" not in image and "@" not in image):
                vulns.append(make_vuln(filepath,
                    find_line(content, image),
                    MEDIUM, cat,
                    f"Service '{svc_name}' uses 'latest' or untagged image",
                    f"Image '{image}' uses mutable tag.",
                    "Pin to a specific version tag.",
                    content, "CWE-829"))

        # Rule 7: volume mounting sensitive paths
        volumes = svc_config.get("volumes", [])
        sensitive_mounts = ["/etc", "/var/run/docker.sock", "/proc", "/sys",
                           "/root", "/home", "/var/log", "/boot", "/dev"]
        for vol in volumes:
            vol_str = str(vol)
            for sm in sensitive_mounts:
                if sm in vol_str:
                    sev = CRITICAL if "docker.sock" in vol_str else HIGH
                    vulns.append(make_vuln(filepath,
                        find_line(content, vol_str),
                        sev, cat,
                        f"Service '{svc_name}' mounts sensitive host path: {sm}",
                        f"Mounting '{sm}' from host gives container access to sensitive host data.",
                        "Avoid mounting sensitive host paths. Use named volumes.",
                        content, "CWE-284"))

        # Rule 8: no restart policy
        if not svc_config.get("restart") and not svc_config.get("deploy", {}).get("restart_policy"):
            vulns.append(make_vuln(filepath,
                find_line(content, f"{svc_name}:") or 1,
                LOW, cat,
                f"Service '{svc_name}' has no restart policy",
                "No restart policy. Container will not auto-restart on failure.",
                "Add restart: unless-stopped or restart: always.",
                content, "CWE-703"))

        # Rule 9: no healthcheck
        if not svc_config.get("healthcheck"):
            vulns.append(make_vuln(filepath,
                find_line(content, f"{svc_name}:") or 1,
                LOW, cat,
                f"Service '{svc_name}' has no healthcheck",
                "No healthcheck defined. Docker cannot monitor container health.",
                "Add a healthcheck with test, interval, and timeout.",
                content, "CWE-703"))

        # Rule 10: dangerous capabilities
        cap_add = svc_config.get("cap_add", [])
        dangerous = ["SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE",
                      "NET_RAW", "SYS_MODULE"]
        for cap in cap_add:
            if cap in dangerous:
                vulns.append(make_vuln(filepath,
                    find_line(content, cap),
                    HIGH, cat,
                    f"Service '{svc_name}' adds dangerous capability: {cap}",
                    f"cap_add {cap} grants elevated privileges.",
                    "Remove unnecessary capabilities.",
                    content, "CWE-250"))

        # Rule: pid mode host
        if svc_config.get("pid") == "host":
            vulns.append(make_vuln(filepath,
                find_line(content, "pid"),
                HIGH, cat,
                f"Service '{svc_name}' uses host PID namespace",
                "Host PID namespace exposes all host processes.",
                "Remove pid: host.",
                content, "CWE-284"))

    return vulns


# ===================================================================
#  XML CONFIG SCANNER (10+ rules)
# ===================================================================
def scan_xml_config(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "XML Config"

    # Try to parse XML
    try:
        # Remove BOM if present
        clean = content.lstrip("\ufeff")
        root = ET.fromstring(clean)
    except ET.ParseError:
        # Fall back to regex scanning
        return _scan_xml_regex(filepath, content)

    root_tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    ns = {"": root.tag.replace(root_tag, "").strip("{}")} if "}" in root.tag else {}

    def find_elements(tag):
        """Find elements regardless of namespace."""
        results = []
        for elem in root.iter():
            local_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if local_tag.lower() == tag.lower():
                results.append(elem)
        return results

    # Rule 1: debug mode
    for compilation in find_elements("compilation"):
        if compilation.get("debug", "").lower() == "true":
            vulns.append(make_vuln(filepath,
                find_line(content, 'debug="true"') or find_line(content, "debug"),
                HIGH, cat,
                "Debug mode enabled in compilation",
                "Debug mode exposes detailed error information and degrades performance.",
                'Set debug="false" in production.',
                content, "CWE-489"))

    # Rule 2: custom errors disabled
    for ce in find_elements("customErrors"):
        mode = ce.get("mode", "").lower()
        if mode in ("off", "remoteonly"):
            vulns.append(make_vuln(filepath,
                find_line(content, "customErrors"),
                HIGH, cat,
                f"Custom errors mode is '{mode}'",
                "Detailed error messages are shown to users, revealing internal details.",
                'Set customErrors mode="On" with a default redirect.',
                content, "CWE-209"))

    # Rule 3: trace enabled
    for trace in find_elements("trace"):
        if trace.get("enabled", "").lower() == "true":
            vulns.append(make_vuln(filepath,
                find_line(content, "trace"),
                HIGH, cat,
                "Trace is enabled",
                "Trace output reveals detailed request/response information.",
                'Set trace enabled="false".',
                content, "CWE-215"))

    # Rule 4: forms auth without SSL
    for auth in find_elements("authentication"):
        if auth.get("mode", "").lower() == "forms":
            forms = auth.find("forms") if auth.find("forms") is not None else None
            # Check for forms sub-elements
            for forms_elem in find_elements("forms"):
                if forms_elem.get("requireSSL", "").lower() != "true":
                    vulns.append(make_vuln(filepath,
                        find_line(content, "forms"),
                        HIGH, cat,
                        "Forms authentication without SSL requirement",
                        "Authentication cookies can be transmitted over unencrypted connections.",
                        'Set requireSSL="true" on the forms element.',
                        content, "CWE-614"))

    # Rule 5: ViewState MAC disabled
    for pages in find_elements("pages"):
        if pages.get("enableViewStateMac", "").lower() == "false":
            vulns.append(make_vuln(filepath,
                find_line(content, "enableViewStateMac"),
                CRITICAL, cat,
                "ViewState MAC validation disabled",
                "Disabling ViewState MAC allows tampering with ViewState data.",
                'Set enableViewStateMac="true" or remove the attribute.',
                content, "CWE-345"))

    # Rule 6: XXE / DTD processing
    # Check for various XML parser settings
    content_lower = content.lower()
    if "dtdprocessing" in content_lower:
        if 'dtdprocessing="parse"' in content_lower or "dtdprocessing.parse" in content_lower:
            vulns.append(make_vuln(filepath,
                find_line(content, "DtdProcessing"),
                CRITICAL, cat,
                "DTD processing enabled (XXE risk)",
                "Enabling DTD processing can lead to XML External Entity (XXE) attacks.",
                "Disable DTD processing or set DtdProcessing.Prohibit.",
                content, "CWE-611"))

    if "resolveexternals" in content_lower and "true" in content_lower:
        vulns.append(make_vuln(filepath,
            find_line(content, "resolveExternals"),
            CRITICAL, cat,
            "External entity resolution enabled",
            "Resolving external entities can lead to XXE attacks.",
            'Set resolveExternals="false".',
            content, "CWE-611"))

    # Rule 7: weak session timeout
    for session in find_elements("sessionState"):
        timeout = session.get("timeout", "")
        if timeout:
            try:
                t = int(timeout)
                if t > 60:
                    vulns.append(make_vuln(filepath,
                        find_line(content, "sessionState"),
                        MEDIUM, cat,
                        f"Session timeout too long ({t} minutes)",
                        f"Session timeout is {t} minutes. Long sessions increase hijacking risk.",
                        "Set session timeout to 20-30 minutes.",
                        content, "CWE-613"))
            except ValueError:
                pass

    # Rule 8: missing HTTPS redirect
    for rule in find_elements("rule"):
        rule_str = ET.tostring(rule, encoding="unicode")
        # Not a vulnerability per se; check if there's NO HTTPS rule
    # Check if httpRedirect or rewrite rules exist for HTTPS
    has_https_redirect = any("https" in ET.tostring(r, encoding="unicode").lower() for r in find_elements("rule"))
    if not has_https_redirect and "system.web" in content.lower():
        vulns.append(make_vuln(filepath, 1, MEDIUM, cat,
            "No HTTPS redirect rule found",
            "No URL rewrite rule to redirect HTTP to HTTPS.",
            "Add an IIS URL Rewrite rule to enforce HTTPS.",
            content, "CWE-319"))

    # Rule 9: hardcoded connection strings
    for conn in find_elements("connectionStrings"):
        for add_elem in conn:
            conn_str = add_elem.get("connectionString", "")
            if conn_str:
                for pat, kind in SECRET_PATTERNS[:6]:
                    if pat.search(conn_str):
                        vulns.append(make_vuln(filepath,
                            find_line(content, conn_str[:30]),
                            HIGH, cat,
                            "Hardcoded credentials in connection string",
                            "Database connection string contains hardcoded credentials.",
                            "Use integrated security or store credentials in encrypted config sections.",
                            content, "CWE-798"))
                        break

    # Rule 10: directory browsing
    for db_elem in find_elements("directoryBrowse"):
        if db_elem.get("enabled", "").lower() == "true":
            vulns.append(make_vuln(filepath,
                find_line(content, "directoryBrowse"),
                MEDIUM, cat,
                "Directory browsing enabled",
                "Users can list directory contents, potentially exposing sensitive files.",
                'Set directoryBrowse enabled="false".',
                content, "CWE-548"))

    # Also run regex checks for things the parser might miss
    vulns.extend(_scan_xml_regex(filepath, content))

    return vulns


def _scan_xml_regex(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "XML Config"

    # Check for hardcoded secrets in XML
    for pat, kind in SECRET_PATTERNS:
        m = pat.search(content)
        if m:
            ln = find_line(content, m.group(0)[:30])
            vulns.append(make_vuln(filepath, ln, HIGH, cat,
                f"Potential hardcoded {kind} in XML config",
                f"Found pattern matching {kind} in configuration file.",
                "Move sensitive values to environment variables or a secrets manager.",
                content, "CWE-798"))

    return vulns


# ===================================================================
#  ANSIBLE SCANNER (10+ rules)
# ===================================================================
def scan_ansible(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "Ansible"

    try:
        docs = list(yaml.safe_load_all(content))
    except Exception as e:
        logger.warning(f"Could not parse Ansible YAML {filepath}: {e}")
        return vulns

    for doc in docs:
        if not isinstance(doc, (dict, list)):
            continue

        tasks = []
        if isinstance(doc, list):
            tasks = doc
        elif isinstance(doc, dict):
            tasks = doc.get("tasks", []) or []
            # Also check pre_tasks, post_tasks, handlers, roles
            tasks += doc.get("pre_tasks", []) or []
            tasks += doc.get("post_tasks", []) or []
            tasks += doc.get("handlers", []) or []
            # Check vars for secrets
            vars_dict = doc.get("vars", {}) or {}
            if isinstance(vars_dict, dict):
                for var_name, var_val in vars_dict.items():
                    if any(kw in var_name.lower() for kw in
                           ["password", "secret", "key", "token", "credential"]):
                        if var_val and not str(var_val).startswith("{{"):
                            vulns.append(make_vuln(filepath,
                                find_line(content, var_name),
                                HIGH, cat,
                                f"Plaintext credential in variable: {var_name}",
                                f"Variable '{var_name}' contains a hardcoded sensitive value.",
                                "Use ansible-vault to encrypt sensitive variables.",
                                content, "CWE-798"))

        for task in tasks:
            if not isinstance(task, dict):
                continue
            task_name = task.get("name", "unnamed")

            # Rule 1: Hardcoded passwords in task parameters
            task_str = json.dumps(task)
            for pat, kind in SECRET_PATTERNS[:6]:
                if pat.search(task_str):
                    # Check it's not a vault reference
                    if "!vault" not in task_str and "{{" not in task_str:
                        vulns.append(make_vuln(filepath,
                            find_line(content, task_name) if task_name != "unnamed" else 1,
                            HIGH, cat,
                            f"Hardcoded {kind} in task '{task_name}'",
                            f"Task contains hardcoded {kind}.",
                            "Use ansible-vault or external secrets management.",
                            content, "CWE-798"))
                        break

            # Rule 2: no_log missing on sensitive tasks
            modules_needing_no_log = ["user", "mysql_user", "postgresql_user",
                                       "uri", "command", "shell", "raw",
                                       "expect", "ldap_passwd"]
            for mod in modules_needing_no_log:
                if mod in task:
                    mod_args = task.get(mod, {})
                    if isinstance(mod_args, dict):
                        has_sensitive = any(
                            kw in str(mod_args).lower()
                            for kw in ["password", "secret", "token"]
                        )
                        if has_sensitive and not task.get("no_log"):
                            vulns.append(make_vuln(filepath,
                                find_line(content, task_name) if task_name != "unnamed" else 1,
                                MEDIUM, cat,
                                f"Missing no_log on sensitive task '{task_name}'",
                                f"Task uses '{mod}' with sensitive data but no_log is not set.",
                                "Add no_log: true to prevent sensitive data in logs.",
                                content, "CWE-532"))

            # Rule 3: shell/command without changed_when
            if any(mod in task for mod in ("shell", "command", "raw")):
                if "changed_when" not in task and "creates" not in task and "removes" not in task:
                    vulns.append(make_vuln(filepath,
                        find_line(content, task_name) if task_name != "unnamed" else 1,
                        LOW, cat,
                        f"shell/command without changed_when in '{task_name}'",
                        "Without changed_when, task always reports 'changed'.",
                        "Add changed_when or use a module instead of shell/command.",
                        content, "CWE-1078"))

            # Rule 4: HTTP instead of HTTPS for repos
            for key in ("url", "repo", "baseurl"):
                val = ""
                for mod_name, mod_args in task.items():
                    if isinstance(mod_args, dict) and key in mod_args:
                        val = str(mod_args.get(key, ""))
                if val.startswith("http://") and "localhost" not in val and "127.0.0.1" not in val:
                    vulns.append(make_vuln(filepath,
                        find_line(content, val[:40]),
                        MEDIUM, cat,
                        f"HTTP URL in task '{task_name}'",
                        f"Using unencrypted HTTP for '{val[:60]}'. Content could be tampered.",
                        "Use HTTPS for all remote URLs.",
                        content, "CWE-319"))

            # Rule 5: disabling host key checking
            env = task.get("environment", {})
            if isinstance(env, dict):
                if env.get("ANSIBLE_HOST_KEY_CHECKING") == "false" or env.get("ANSIBLE_HOST_KEY_CHECKING") == False:
                    vulns.append(make_vuln(filepath,
                        find_line(content, "ANSIBLE_HOST_KEY_CHECKING"),
                        HIGH, cat,
                        f"Host key checking disabled in '{task_name}'",
                        "Disabling SSH host key checking allows MITM attacks.",
                        "Keep host key checking enabled.",
                        content, "CWE-295"))

            # Rule 6: weak file permissions
            for mod in ("file", "copy", "template"):
                if mod in task:
                    mod_args = task.get(mod, {})
                    if isinstance(mod_args, dict):
                        file_mode = str(mod_args.get("mode", ""))
                        if file_mode in ("0777", "777", "0666", "666", "0776", "776"):
                            vulns.append(make_vuln(filepath,
                                find_line(content, file_mode),
                                HIGH, cat,
                                f"Weak file permissions ({file_mode}) in '{task_name}'",
                                f"File permissions {file_mode} are overly permissive.",
                                "Use restrictive permissions (e.g., 0644 or 0755).",
                                content, "CWE-732"))

            # Rule 7: become without become_user
            if task.get("become") and not task.get("become_user"):
                vulns.append(make_vuln(filepath,
                    find_line(content, "become") if "become" in content else 1,
                    LOW, cat,
                    f"become without become_user in '{task_name}'",
                    "Using 'become' without 'become_user' defaults to root.",
                    "Specify become_user with the least-privileged user needed.",
                    content, "CWE-250"))

    # Rule 8: unencrypted vault check (regex on entire content)
    if "vault_password" in content.lower() and "!vault" not in content:
        vulns.append(make_vuln(filepath,
            find_line(content, "vault_password"),
            HIGH, cat,
            "Vault password appears to be stored in plaintext",
            "Vault password should not be in playbook files.",
            "Use --ask-vault-pass, vault-password-file, or environment variables.",
            content, "CWE-798"))

    # General secret scan
    for pat, kind in SECRET_PATTERNS:
        m = pat.search(content)
        if m:
            # Skip vault-encrypted values
            match_line_idx = find_line(content, m.group(0)[:30])
            lines = content.split("\n")
            if match_line_idx <= len(lines):
                line_content = lines[match_line_idx - 1]
                if "!vault" in line_content or "{{" in line_content:
                    continue
            vulns.append(make_vuln(filepath, match_line_idx, HIGH, cat,
                f"Potential hardcoded {kind} in Ansible file",
                f"Found pattern matching {kind}.",
                "Use ansible-vault or external secrets management.",
                content, "CWE-798"))

    return vulns


# ===================================================================
#  GENERAL CONFIG SCANNER (YAML/JSON/INI/TOML/Nginx/Apache)
# ===================================================================
def scan_general_config(filepath: str, content: str, file_type: str) -> List[dict]:
    vulns = []
    cat = "Configuration"

    # Parse if possible
    parsed = None
    if file_type in ("yaml", "yml"):
        try:
            parsed = yaml.safe_load(content)
        except Exception:
            pass
    elif file_type == "json":
        try:
            parsed = json.loads(content)
        except Exception:
            pass
    elif file_type == "toml":
        try:
            parsed = toml.loads(content)
        except Exception:
            pass
    elif file_type == "ini":
        try:
            cp = configparser.ConfigParser()
            cp.read_string(content)
            parsed = {s: dict(cp.items(s)) for s in cp.sections()}
        except Exception:
            pass

    # Deep inspection of parsed config
    if parsed and isinstance(parsed, dict):
        vulns.extend(_scan_config_dict(filepath, content, parsed, cat))

    # Regex-based scanning for all config types
    vulns.extend(_scan_config_regex(filepath, content, file_type, cat))

    # Nginx-specific
    if file_type == "nginx" or "nginx" in filepath.lower():
        vulns.extend(_scan_nginx(filepath, content))

    # Apache-specific
    if file_type == "apache" or "apache" in filepath.lower() or "httpd" in filepath.lower():
        vulns.extend(_scan_apache(filepath, content))

    return vulns


def _scan_config_dict(filepath: str, content: str, d: dict, cat: str, path: str = "") -> List[dict]:
    """Recursively scan a config dictionary for vulnerabilities."""
    vulns = []

    for key, value in d.items():
        full_key = f"{path}.{key}" if path else key
        key_lower = key.lower()

        # Rule 1: hardcoded secrets
        if any(kw in key_lower for kw in
               ["password", "passwd", "secret", "api_key", "apikey",
                "token", "private_key", "access_key", "credential",
                "auth_token", "connection_string", "encryption_key"]):
            if value and isinstance(value, str) and len(value) >= 4:
                # Skip if it's a reference/placeholder
                if not any(p in str(value) for p in ["${", "{{", "vault:", "<", "CHANGE_ME", "TODO", "xxx"]):
                    vulns.append(make_vuln(filepath,
                        find_line(content, key),
                        HIGH, cat,
                        f"Hardcoded secret in config: {full_key}",
                        f"Key '{full_key}' contains what appears to be a hardcoded secret value.",
                        "Use environment variables or a secrets manager.",
                        content, "CWE-798"))

        # Rule 2: debug mode
        if key_lower in ("debug", "debug_mode", "debugging"):
            if value in (True, "true", "True", "1", 1, "yes", "on"):
                vulns.append(make_vuln(filepath,
                    find_line(content, key),
                    MEDIUM, cat,
                    f"Debug mode enabled: {full_key}",
                    "Debug mode may expose sensitive information in production.",
                    "Disable debug mode in production configurations.",
                    content, "CWE-489"))

        # Rule 5: overly permissive CORS
        if key_lower in ("cors", "cors_origin", "allowed_origins", "access_control_allow_origin"):
            if value in ("*", ["*"]) or (isinstance(value, str) and value == "*"):
                vulns.append(make_vuln(filepath,
                    find_line(content, key),
                    MEDIUM, cat,
                    f"Overly permissive CORS: {full_key}",
                    "CORS allows requests from any origin.",
                    "Restrict CORS to specific trusted domains.",
                    content, "CWE-942"))

        # Rule 6: weak SSL/TLS
        if key_lower in ("ssl_version", "tls_version", "min_tls_version", "ssl_protocols"):
            val_str = str(value).lower()
            if any(weak in val_str for weak in ["sslv2", "sslv3", "tlsv1.0", "tlsv1 ", "tls1.0", "ssl3"]):
                vulns.append(make_vuln(filepath,
                    find_line(content, key),
                    HIGH, cat,
                    f"Weak SSL/TLS version: {full_key}",
                    f"Configuration uses deprecated/weak protocol: {value}",
                    "Use TLSv1.2 or TLSv1.3 only.",
                    content, "CWE-326"))

        # Rule 7: disabled security features
        if key_lower in ("verify_ssl", "ssl_verify", "check_certificate",
                         "tls_verify", "insecure_skip_verify"):
            if value in (False, "false", "False", "0", 0, "no", "off"):
                vulns.append(make_vuln(filepath,
                    find_line(content, key),
                    HIGH, cat,
                    f"SSL verification disabled: {full_key}",
                    "SSL/TLS certificate verification is disabled.",
                    "Enable SSL verification to prevent MITM attacks.",
                    content, "CWE-295"))

        # Recurse into nested dicts/lists
        if isinstance(value, dict):
            vulns.extend(_scan_config_dict(filepath, content, value, cat, full_key))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    vulns.extend(_scan_config_dict(filepath, content, item, cat, full_key))

    return vulns


def _scan_config_regex(filepath: str, content: str, file_type: str, cat: str) -> List[dict]:
    """Regex-based scanning for config files."""
    vulns = []
    lines = content.split("\n")

    # Rule 1: Secret patterns
    for pat, kind in SECRET_PATTERNS:
        for i, line in enumerate(lines):
            m = pat.search(line)
            if m:
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";"):
                    continue
                vulns.append(make_vuln(filepath, i + 1, HIGH, cat,
                    f"Potential hardcoded {kind}",
                    f"Line contains pattern matching {kind}.",
                    "Use environment variables or a secrets manager.",
                    content, "CWE-798"))
                break  # One finding per pattern type

    # Rule 3: Insecure URLs
    http_pat = re.compile(r'https?://\S+', re.I)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";"):
            continue
        for m in http_pat.finditer(line):
            url = m.group(0).strip('"').strip("'").rstrip(",").rstrip(")")
            if url.startswith("http://") and not any(
                local in url for local in ["localhost", "127.0.0.1", "0.0.0.0",
                                           "example.com", "example.org", "schemas."]):
                vulns.append(make_vuln(filepath, i + 1, MEDIUM, cat,
                    "Insecure HTTP URL detected",
                    f"Using unencrypted HTTP: {url[:80]}",
                    "Use HTTPS for all remote connections.",
                    content, "CWE-319"))
                break

    # Rule 4: Default credentials
    default_creds = [
        (re.compile(r'admin[:/]admin', re.I), "admin/admin"),
        (re.compile(r'root[:/]root', re.I), "root/root"),
        (re.compile(r'user[:/]password', re.I), "user/password"),
        (re.compile(r'test[:/]test', re.I), "test/test"),
        (re.compile(r'guest[:/]guest', re.I), "guest/guest"),
        (re.compile(r'password123', re.I), "password123"),
        (re.compile(r'changeme', re.I), "changeme"),
        (re.compile(r'default[_-]?password', re.I), "default password"),
    ]
    for pat, cred in default_creds:
        m = pat.search(content)
        if m:
            vulns.append(make_vuln(filepath,
                find_line(content, m.group(0)[:20]),
                HIGH, cat,
                f"Default credentials detected: {cred}",
                f"Configuration contains what appears to be default credentials.",
                "Use strong, unique credentials.",
                content, "CWE-1392"))

    # Rule 8: Exposed internal endpoints
    internal_patterns = [
        (re.compile(r'(?:admin|management|actuator|debug|internal|swagger|graphql)\s*[=:]\s*(?:true|enabled|0\.0\.0\.0)', re.I),
         "internal endpoint exposed"),
    ]
    for pat, desc in internal_patterns:
        m = pat.search(content)
        if m:
            vulns.append(make_vuln(filepath,
                find_line(content, m.group(0)[:30]),
                MEDIUM, cat,
                f"Potentially exposed {desc}",
                "Internal/management endpoint appears to be enabled or publicly accessible.",
                "Disable or restrict access to internal endpoints in production.",
                content, "CWE-284"))

    return vulns


def _scan_nginx(filepath: str, content: str) -> List[dict]:
    """Scan nginx configuration files."""
    vulns = []
    cat = "Nginx Config"
    lines = content.split("\n")

    # Check for server_tokens on
    if re.search(r'server_tokens\s+on', content):
        vulns.append(make_vuln(filepath,
            find_line(content, "server_tokens"),
            LOW, cat,
            "Server tokens enabled (version disclosure)",
            "Nginx server version is disclosed in response headers.",
            "Set server_tokens off;",
            content, "CWE-200"))

    # Check for missing security headers
    security_headers = {
        "X-Frame-Options": ("add_header X-Frame-Options", MEDIUM, "Clickjacking protection"),
        "X-Content-Type-Options": ("add_header X-Content-Type-Options", LOW, "MIME sniffing protection"),
        "X-XSS-Protection": ("add_header X-XSS-Protection", LOW, "XSS filter"),
        "Strict-Transport-Security": ("add_header Strict-Transport-Security", MEDIUM, "HSTS"),
        "Content-Security-Policy": ("add_header Content-Security-Policy", MEDIUM, "CSP"),
    }
    for header_name, (search_str, severity, desc) in security_headers.items():
        if search_str.lower() not in content.lower():
            vulns.append(make_vuln(filepath, 1, severity, cat,
                f"Missing {header_name} header",
                f"{desc} header is not configured.",
                f"Add: add_header {header_name} <appropriate value>;",
                content, "CWE-693"))

    # SSL/TLS issues
    if "ssl_protocols" in content:
        ln = find_line(content, "ssl_protocols")
        line_content = lines[ln - 1] if ln <= len(lines) else ""
        if any(proto in line_content.lower() for proto in ["sslv2", "sslv3", "tlsv1 ", "tlsv1;"]):
            vulns.append(make_vuln(filepath, ln, HIGH, cat,
                "Weak SSL/TLS protocol enabled",
                "Deprecated SSL/TLS protocol version is enabled.",
                "Use only TLSv1.2 and TLSv1.3.",
                content, "CWE-326"))

    # Weak ciphers
    if re.search(r'ssl_ciphers\s+.*(?:DES|RC4|MD5|NULL|EXPORT|aNULL|eNULL)', content, re.I):
        vulns.append(make_vuln(filepath,
            find_line(content, "ssl_ciphers"),
            HIGH, cat,
            "Weak SSL ciphers configured",
            "Nginx is configured with weak or deprecated cipher suites.",
            "Use modern cipher suites. Consider using Mozilla SSL Configuration Generator.",
            content, "CWE-327"))

    # autoindex on
    if re.search(r'autoindex\s+on', content):
        vulns.append(make_vuln(filepath,
            find_line(content, "autoindex"),
            MEDIUM, cat,
            "Directory listing enabled (autoindex on)",
            "Directory contents can be listed by anyone.",
            "Set autoindex off;",
            content, "CWE-548"))

    # Missing rate limiting
    if "limit_req" not in content and "limit_conn" not in content:
        if "server" in content:
            vulns.append(make_vuln(filepath, 1, LOW, cat,
                "No rate limiting configured",
                "No limit_req or limit_conn directives found.",
                "Add rate limiting to prevent abuse and DoS attacks.",
                content, "CWE-770"))

    # proxy_pass to HTTP
    for m in re.finditer(r'proxy_pass\s+http://[^;]+', content):
        if "localhost" not in m.group() and "127.0.0.1" not in m.group():
            vulns.append(make_vuln(filepath,
                find_line(content, m.group()[:30]),
                MEDIUM, cat,
                "proxy_pass uses unencrypted HTTP",
                "Traffic between nginx and upstream is unencrypted.",
                "Use HTTPS for proxy_pass to upstream servers.",
                content, "CWE-319"))

    return vulns


def _scan_apache(filepath: str, content: str) -> List[dict]:
    """Scan Apache httpd configuration files."""
    vulns = []
    cat = "Apache Config"

    # ServerSignature On
    if re.search(r'ServerSignature\s+On', content, re.I):
        vulns.append(make_vuln(filepath,
            find_line(content, "ServerSignature"),
            LOW, cat,
            "Server signature enabled",
            "Apache version info is shown in error pages.",
            "Set ServerSignature Off.",
            content, "CWE-200"))

    # ServerTokens Full/OS/Major
    if re.search(r'ServerTokens\s+(Full|OS|Major|Minor)', content, re.I):
        vulns.append(make_vuln(filepath,
            find_line(content, "ServerTokens"),
            LOW, cat,
            "Server tokens expose version info",
            "Apache reveals version information in HTTP headers.",
            "Set ServerTokens Prod.",
            content, "CWE-200"))

    # Options +Indexes
    if re.search(r'Options\s+.*Indexes', content) and "-Indexes" not in content:
        vulns.append(make_vuln(filepath,
            find_line(content, "Indexes"),
            MEDIUM, cat,
            "Directory listing enabled",
            "Apache will list directory contents when no index file exists.",
            "Use Options -Indexes.",
            content, "CWE-548"))

    # AllowOverride All in sensitive directories
    if re.search(r'AllowOverride\s+All', content):
        vulns.append(make_vuln(filepath,
            find_line(content, "AllowOverride All"),
            LOW, cat,
            "AllowOverride All is permissive",
            ".htaccess files can override any server configuration.",
            "Use AllowOverride with specific directives only.",
            content, "CWE-732"))

    # SSLProtocol with weak versions
    if re.search(r'SSLProtocol\s+.*(?:SSLv2|SSLv3|TLSv1\s)', content, re.I):
        vulns.append(make_vuln(filepath,
            find_line(content, "SSLProtocol"),
            HIGH, cat,
            "Weak SSL/TLS protocol enabled",
            "Deprecated protocol version is configured.",
            "Use only TLSv1.2 and TLSv1.3.",
            content, "CWE-326"))

    # Require all granted without restrictions
    if re.search(r'Require\s+all\s+granted', content, re.I):
        vulns.append(make_vuln(filepath,
            find_line(content, "Require all granted"),
            LOW, cat,
            "Unrestricted access (Require all granted)",
            "Directory is accessible without any restrictions.",
            "Use IP-based or authentication restrictions where appropriate.",
            content, "CWE-284"))

    return vulns


# ===================================================================
#  CLOUDFORMATION SCANNER
# ===================================================================
def scan_cloudformation(filepath: str, content: str) -> List[dict]:
    vulns = []
    cat = "CloudFormation"

    try:
        doc = yaml.safe_load(content)
    except Exception:
        try:
            doc = json.loads(content)
        except Exception:
            return vulns

    if not isinstance(doc, dict):
        return vulns

    resources = doc.get("Resources", {}) or {}

    for res_name, res_def in resources.items():
        if not isinstance(res_def, dict):
            continue
        res_type = res_def.get("Type", "")
        props = res_def.get("Properties", {}) or {}

        # S3 bucket
        if res_type == "AWS::S3::Bucket":
            # Public access
            acl = props.get("AccessControl", "")
            if acl in ("PublicRead", "PublicReadWrite"):
                vulns.append(make_vuln(filepath,
                    find_line(content, acl), CRITICAL, cat,
                    f"S3 bucket '{res_name}' has public access",
                    f"Bucket ACL is '{acl}'.",
                    "Set AccessControl to Private.",
                    content, "CWE-284"))
            # No encryption
            if not props.get("BucketEncryption"):
                vulns.append(make_vuln(filepath,
                    find_line(content, res_name), MEDIUM, cat,
                    f"S3 bucket '{res_name}' not encrypted",
                    "No BucketEncryption configured.",
                    "Add BucketEncryption with ServerSideEncryptionConfiguration.",
                    content, "CWE-311"))
            # No versioning
            vc = props.get("VersioningConfiguration", {})
            if not vc or vc.get("Status") != "Enabled":
                vulns.append(make_vuln(filepath,
                    find_line(content, res_name), LOW, cat,
                    f"S3 bucket '{res_name}' versioning not enabled",
                    "Versioning is not enabled.",
                    "Enable versioning for data protection.",
                    content, "CWE-693"))

        # Security Group
        if res_type == "AWS::EC2::SecurityGroup":
            ingress_rules = props.get("SecurityGroupIngress", []) or []
            for rule in ingress_rules:
                if not isinstance(rule, dict):
                    continue
                cidr = rule.get("CidrIp", "")
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                if cidr == "0.0.0.0/0":
                    vulns.append(make_vuln(filepath,
                        find_line(content, "0.0.0.0/0"), HIGH, cat,
                        f"Security group '{res_name}' open to 0.0.0.0/0",
                        "Unrestricted ingress from the internet.",
                        "Restrict CIDR to known IP ranges.",
                        content, "CWE-284"))
                    if from_port == 22 or to_port == 22:
                        vulns.append(make_vuln(filepath,
                            find_line(content, "22"), CRITICAL, cat,
                            f"SSH open to world in '{res_name}'",
                            "SSH port 22 is accessible from any IP.",
                            "Restrict SSH to specific IPs.",
                            content, "CWE-284"))

        # RDS
        if res_type == "AWS::RDS::DBInstance":
            if props.get("PubliclyAccessible") in (True, "true"):
                vulns.append(make_vuln(filepath,
                    find_line(content, "PubliclyAccessible"), CRITICAL, cat,
                    f"RDS '{res_name}' is publicly accessible",
                    "Database is exposed to the internet.",
                    "Set PubliclyAccessible to false.",
                    content, "CWE-284"))
            if not props.get("StorageEncrypted"):
                vulns.append(make_vuln(filepath,
                    find_line(content, res_name), MEDIUM, cat,
                    f"RDS '{res_name}' storage not encrypted",
                    "Database storage is not encrypted.",
                    "Set StorageEncrypted to true.",
                    content, "CWE-311"))

        # IAM
        if res_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            policy_doc = props.get("PolicyDocument", {})
            policy_str = json.dumps(policy_doc)
            if '"*"' in policy_str and '"Allow"' in policy_str:
                vulns.append(make_vuln(filepath,
                    find_line(content, '"*"'), CRITICAL, cat,
                    f"IAM policy '{res_name}' uses wildcard permissions",
                    "Policy grants access to all resources/actions.",
                    "Use least-privilege permissions.",
                    content, "CWE-250"))

        # Lambda
        if res_type == "AWS::Lambda::Function":
            if not props.get("VpcConfig"):
                vulns.append(make_vuln(filepath,
                    find_line(content, res_name), MEDIUM, cat,
                    f"Lambda '{res_name}' not in VPC",
                    "Lambda runs outside VPC.",
                    "Add VpcConfig with SubnetIds and SecurityGroupIds.",
                    content, "CWE-284"))

    # Check for hardcoded secrets in parameters
    params = doc.get("Parameters", {}) or {}
    for param_name, param_def in params.items():
        if isinstance(param_def, dict):
            default = param_def.get("Default", "")
            if default and any(kw in param_name.lower() for kw in
                              ["password", "secret", "key", "token"]):
                if param_def.get("NoEcho") != True:
                    vulns.append(make_vuln(filepath,
                        find_line(content, param_name), HIGH, cat,
                        f"Parameter '{param_name}' default value not masked",
                        "Sensitive parameter has a default value and NoEcho is not set.",
                        "Set NoEcho: true and remove default values for secrets.",
                        content, "CWE-798"))

    return vulns


# ===================================================================
#  HELM CHART SCANNER
# ===================================================================
def scan_helm(filepath: str, content: str) -> List[dict]:
    """Scan Helm values.yaml and chart templates."""
    vulns = []
    cat = "Helm Chart"

    # If it's a values.yaml, check for insecure defaults
    if "values" in filepath.lower():
        try:
            doc = yaml.safe_load(content)
        except Exception:
            return vulns

        if isinstance(doc, dict):
            vulns.extend(_scan_helm_values(filepath, content, doc))

    # Templates contain Go templating, scan as Kubernetes
    # but also check for common Helm issues
    if "{{" in content and "}}" in content:
        # Check for hardcoded values that should be templated
        for pat, kind in SECRET_PATTERNS[:6]:
            m = pat.search(content)
            if m:
                # Check if it's inside a template expression
                match_pos = m.start()
                before = content[:match_pos]
                if "{{" not in before[max(0, match_pos-50):match_pos]:
                    vulns.append(make_vuln(filepath,
                        find_line(content, m.group(0)[:30]),
                        HIGH, cat,
                        f"Hardcoded {kind} in Helm template",
                        f"Value should be templated via values.yaml, not hardcoded.",
                        "Use {{ .Values.xxx }} for sensitive configuration.",
                        content, "CWE-798"))
    else:
        # Pure YAML - might be Kubernetes manifest in chart
        if "kind:" in content and "apiVersion:" in content:
            vulns.extend(scan_kubernetes(filepath, content))

    return vulns


def _scan_helm_values(filepath: str, content: str, values: dict, path: str = "") -> List[dict]:
    """Recursively scan Helm values for issues."""
    vulns = []
    cat = "Helm Chart"

    for key, val in values.items():
        full_key = f"{path}.{key}" if path else key
        key_lower = key.lower()

        # Check for insecure defaults
        if key_lower in ("replicas", "replicacount") and val == 1:
            vulns.append(make_vuln(filepath,
                find_line(content, key), LOW, cat,
                f"Single replica configured: {full_key}",
                "Running a single replica provides no high availability.",
                "Consider at least 2 replicas for production.",
                content, "CWE-693"))

        if key_lower == "enabled" and val == False and path:
            parent = path.split(".")[-1].lower()
            if any(sec in parent for sec in ["networkpolicy", "podsecurity", "rbac",
                                              "tls", "ssl", "auth", "securitycontext"]):
                vulns.append(make_vuln(filepath,
                    find_line(content, key), MEDIUM, cat,
                    f"Security feature disabled: {full_key}",
                    f"Security-related feature '{path}' is disabled.",
                    "Enable security features in production.",
                    content, "CWE-693"))

        # Hardcoded secrets
        if any(kw in key_lower for kw in ["password", "secret", "token", "key", "credential"]):
            if val and isinstance(val, str) and val not in ("", "CHANGE_ME", "changeme"):
                vulns.append(make_vuln(filepath,
                    find_line(content, key), HIGH, cat,
                    f"Hardcoded secret in values: {full_key}",
                    "Sensitive value is set in values.yaml.",
                    "Use Helm secrets plugin or external secret management.",
                    content, "CWE-798"))

        if isinstance(val, dict):
            vulns.extend(_scan_helm_values(filepath, content, val, full_key))

    return vulns


# ===================================================================
#  FILE TYPE DETECTION
# ===================================================================
def detect_file_type(filepath: str, content: str) -> str:
    """Detect the type of IaC/config file."""
    fname = os.path.basename(filepath).lower()
    fpath = filepath.lower()

    # Explicit file names
    if fname == "dockerfile" or fname.startswith("dockerfile."):
        return "dockerfile"
    if fname == "docker-compose.yml" or fname == "docker-compose.yaml" or \
       fname.startswith("docker-compose") and (fname.endswith(".yml") or fname.endswith(".yaml")):
        return "docker-compose"
    if fname.endswith(".tf") or fname.endswith(".tf.json"):
        return "terraform"
    if fname == "values.yaml" or fname == "values.yml" or \
       "chart" in fpath or "helm" in fpath or "templates" in fpath:
        if fname.endswith((".yaml", ".yml")):
            return "helm"
    if fname.endswith(".yaml") or fname.endswith(".yml"):
        # Check if it's Kubernetes
        if any(kw in content[:500] for kw in ["apiVersion:", "kind:", "metadata:"]):
            return "kubernetes"
        # Check if it's Ansible
        if any(kw in content[:500] for kw in ["hosts:", "tasks:", "roles:",
                                               "become:", "- name:", "ansible"]):
            return "ansible"
        # Check if it's CloudFormation
        if "AWSTemplateFormatVersion" in content or "AWS::" in content:
            return "cloudformation"
        return "yaml"
    if fname.endswith(".json"):
        # Check CloudFormation
        if "AWSTemplateFormatVersion" in content or "AWS::" in content:
            return "cloudformation"
        return "json"
    if fname.endswith(".xml") or fname.endswith(".config") or fname.endswith(".csproj") or \
       fname.endswith(".cscfg") or fname == "web.config" or fname == "app.config":
        return "xml"
    if fname.endswith(".toml"):
        return "toml"
    if fname.endswith(".ini") or fname.endswith(".cfg") or fname.endswith(".conf"):
        # Check if nginx
        if "nginx" in fpath or "server {" in content or "location /" in content:
            return "nginx"
        # Check if Apache
        if "apache" in fpath or "httpd" in fpath or \
           "VirtualHost" in content or "DocumentRoot" in content:
            return "apache"
        if fname.endswith(".ini") or fname.endswith(".cfg"):
            return "ini"
        return "nginx"  # .conf files default to nginx-like
    if "nginx" in fname:
        return "nginx"
    if "apache" in fname or "httpd" in fname:
        return "apache"
    if fname == ".htaccess":
        return "apache"
    if fname == "ansible.cfg":
        return "ini"
    if fname.endswith(".hcl"):
        return "terraform"

    return "unknown"


# ===================================================================
#  MAIN SCAN ORCHESTRATOR
# ===================================================================
def scan_files(files: Dict[str, str], scan_id: str) -> ScanResponse:
    """Scan all provided files and aggregate results."""
    import time
    start = time.time()

    all_vulns = []

    for filepath, content in files.items():
        if not content or not content.strip():
            continue

        file_type = detect_file_type(filepath, content)
        logger.info(f"Scanning {filepath} as {file_type}")

        try:
            if file_type == "dockerfile":
                all_vulns.extend(scan_dockerfile(filepath, content))
            elif file_type == "terraform":
                all_vulns.extend(scan_terraform(filepath, content))
            elif file_type == "kubernetes":
                all_vulns.extend(scan_kubernetes(filepath, content))
            elif file_type == "docker-compose":
                all_vulns.extend(scan_docker_compose(filepath, content))
            elif file_type == "xml":
                all_vulns.extend(scan_xml_config(filepath, content))
            elif file_type == "ansible":
                all_vulns.extend(scan_ansible(filepath, content))
            elif file_type == "cloudformation":
                all_vulns.extend(scan_cloudformation(filepath, content))
            elif file_type == "helm":
                all_vulns.extend(scan_helm(filepath, content))
            elif file_type in ("yaml", "json", "toml", "ini", "nginx", "apache"):
                all_vulns.extend(scan_general_config(filepath, content, file_type))
            else:
                # Try general config scan as fallback
                all_vulns.extend(scan_general_config(filepath, content, "unknown"))
        except Exception as e:
            logger.error(f"Error scanning {filepath}: {e}\n{traceback.format_exc()}")

    elapsed = time.time() - start

    # Deduplicate by (file, line, title)
    seen = set()
    unique_vulns = []
    for v in all_vulns:
        key = (v["file"], v["line"], v["title"])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    # Sort: Critical > High > Medium > Low > Info
    severity_order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
    unique_vulns.sort(key=lambda v: (severity_order.get(v["severity"], 5), v["file"], v["line"]))

    summary = {
        "totalFiles": len(files),
        "totalVulnerabilities": len(unique_vulns),
        "critical": sum(1 for v in unique_vulns if v["severity"] == CRITICAL),
        "high": sum(1 for v in unique_vulns if v["severity"] == HIGH),
        "medium": sum(1 for v in unique_vulns if v["severity"] == MEDIUM),
        "low": sum(1 for v in unique_vulns if v["severity"] == LOW),
        "info": sum(1 for v in unique_vulns if v["severity"] == INFO),
        "fileTypes": {},
    }

    # Count by file type
    for filepath in files:
        ft = detect_file_type(filepath, files[filepath])
        summary["fileTypes"][ft] = summary["fileTypes"].get(ft, 0) + 1

    return ScanResponse(
        scanId=scan_id,
        vulnerabilities=unique_vulns,
        summary=summary,
        scanDuration=round(elapsed, 3),
    )


# ===================================================================
#  API ENDPOINTS
# ===================================================================
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "IaC SAST Scanner",
        "version": "1.0.0",
        "supportedTypes": [
            "Dockerfile", "Terraform (.tf)", "Kubernetes YAML",
            "Helm Charts", "CloudFormation", "Ansible",
            "Docker Compose", "XML Config", "YAML Config",
            "TOML", "INI", "Nginx Config", "Apache Config"
        ],
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/scan")
async def scan(request: ScanRequest):
    scan_id = request.scanId or str(uuid.uuid4())
    logger.info(f"Starting scan {scan_id} with {len(request.files)} files")

    try:
        result = scan_files(request.files, scan_id)
        logger.info(
            f"Scan {scan_id} complete: {result.summary['totalVulnerabilities']} vulnerabilities "
            f"in {result.scanDuration}s"
        )
        return result
    except Exception as e:
        logger.error(f"Scan failed: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


# ===================================================================
#  MAIN
# ===================================================================
if __name__ == "__main__":
    import uvicorn
    logger.info("Starting IaC SAST Scanner on port 9019")
    uvicorn.run(app, host="0.0.0.0", port=9019, log_level="info")
