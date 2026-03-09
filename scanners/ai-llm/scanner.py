#!/usr/bin/env python3
"""
Offensive360 AI/LLM Technology SAST Scanner
Comprehensive static analysis for AI/ML/LLM applications.
Scans Python, JavaScript/TypeScript, and config files for AI-specific security issues.
FastAPI server on port 9021.
"""

import os
import re
import uuid
import json
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("ai-llm-scanner")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class Finding:
    rule_id: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    column: int = 0
    end_line: int = 0
    code_snippet: str = ""
    remediation: str = ""
    cwe_id: str = ""
    owasp: str = ""
    references: List[str] = field(default_factory=list)

class ScanRequest(BaseModel):
    files: Dict[str, str]
    scanId: str = ""

class ScanResponse(BaseModel):
    scanId: str
    totalFiles: int
    totalFindings: int
    findings: List[Dict[str, Any]]
    summary: Dict[str, int]


# ---------------------------------------------------------------------------
# AI/LLM Vulnerability Rules
# ---------------------------------------------------------------------------
AI_LLM_RULES = [
    # ========================================================================
    # PROMPT INJECTION
    # ========================================================================
    {
        "id": "AI-PINJ-001",
        "category": "Prompt Injection",
        "title": "User Input Directly in Prompt Template",
        "description": "User input is concatenated or f-string interpolated directly into a prompt template without sanitization, allowing prompt injection attacks.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:prompt|system_message|system_prompt|instruction)\s*(?:=|:)\s*(?:f['"]{1,3}|['"]{1,3}\s*\+\s*|['"]{1,3}[^'"]*\{)[^'"]*(?:user_input|user_message|query|question|input|request|message)\b""",
        "cwe_id": "CWE-77",
        "owasp": "LLM01:2025-Prompt Injection",
        "remediation": "Sanitize user input before including in prompts. Use structured prompt templates with clear delimiters. Implement input validation and output filtering.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py", ".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "AI-PINJ-002",
        "category": "Prompt Injection",
        "title": "Unsanitized Input in ChatCompletion Messages",
        "description": "User input is placed directly into chat messages without sanitization, enabling prompt injection.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:messages|chat_history)\s*(?:=|\.\s*append)\s*\[?\s*\{[^}]*(?:"role"\s*:\s*"user"|'role'\s*:\s*'user')[^}]*(?:f['""]|['""]?\s*\+\s*|['""][^'""]*\{)[^}]*(?:user_input|input|query|request)""",
        "cwe_id": "CWE-77",
        "owasp": "LLM01:2025-Prompt Injection",
        "remediation": "Validate and sanitize user input. Use content moderation APIs. Implement prompt guards.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "AI-PINJ-003",
        "category": "Prompt Injection",
        "title": "Template String with User Content in System Prompt",
        "description": "System prompt is constructed using template strings or format() with user-controlled content, allowing system prompt manipulation.",
        "severity": "Critical",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:system|system_prompt|system_message)\s*=\s*(?:f['"]{1,3}|['"]{1,3}\.format\(|['"]{1,3}\s*%\s*)""",
        "cwe_id": "CWE-77",
        "owasp": "LLM01:2025-Prompt Injection",
        "remediation": "Keep system prompts static. Never interpolate user input into system messages. Use structured message arrays.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py", ".js", ".ts"],
    },

    # ========================================================================
    # LLM API KEY EXPOSURE
    # ========================================================================
    {
        "id": "AI-KEY-001",
        "category": "API Key Exposure",
        "title": "OpenAI API Key Hardcoded",
        "description": "An OpenAI API key (sk-...) is hardcoded in the source code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?:openai[._]?api[._]?key|api_key|apikey|OPENAI_API_KEY)\s*(?:=|:)\s*['"](sk-[a-zA-Z0-9_-]{20,})['"]""",
        "cwe_id": "CWE-798",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault) for API keys. Never hardcode keys.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "file_types": [".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml", ".json", ".toml"],
    },
    {
        "id": "AI-KEY-002",
        "category": "API Key Exposure",
        "title": "Anthropic API Key Hardcoded",
        "description": "An Anthropic API key (sk-ant-...) is hardcoded in the source code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?:anthropic[._]?api[._]?key|api_key|ANTHROPIC_API_KEY)\s*(?:=|:)\s*['"](sk-ant-[a-zA-Z0-9_-]{20,})['"]""",
        "cwe_id": "CWE-798",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Use environment variables or a secrets manager for API keys. Never hardcode keys.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "file_types": [".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json"],
    },
    {
        "id": "AI-KEY-003",
        "category": "API Key Exposure",
        "title": "HuggingFace API Token Hardcoded",
        "description": "A HuggingFace API token (hf_...) is hardcoded in the source code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?:huggingface[._]?token|hf[._]?token|HF_TOKEN|HUGGINGFACE_TOKEN)\s*(?:=|:)\s*['"](hf_[a-zA-Z0-9]{20,})['"]""",
        "cwe_id": "CWE-798",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Use environment variables for HuggingFace tokens. Use huggingface-cli login for local development.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "file_types": [".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json"],
    },
    {
        "id": "AI-KEY-004",
        "category": "API Key Exposure",
        "title": "Cohere API Key Hardcoded",
        "description": "A Cohere API key is hardcoded in the source code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?:cohere[._]?api[._]?key|COHERE_API_KEY)\s*(?:=|:)\s*['"][a-zA-Z0-9]{30,}['"]""",
        "cwe_id": "CWE-798",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Use environment variables or a secrets manager for Cohere API keys.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "file_types": [".py", ".js", ".ts", ".env"],
    },
    {
        "id": "AI-KEY-005",
        "category": "API Key Exposure",
        "title": "Generic AI API Key Pattern",
        "description": "An API key for an AI service appears to be hardcoded in source code.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:api[._]?key|secret[._]?key|access[._]?token)\s*(?:=|:)\s*['"][a-zA-Z0-9_-]{32,}['"]""",
        "cwe_id": "CWE-798",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Use environment variables or a secrets manager. Never hardcode API keys or tokens.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "file_types": [".py", ".js", ".ts", ".env", ".yaml", ".yml"],
    },

    # ========================================================================
    # MODEL POISONING / INSECURE MODEL LOADING
    # ========================================================================
    {
        "id": "AI-MODEL-001",
        "category": "Insecure Model Loading",
        "title": "pickle.load Used for Model Loading",
        "description": "pickle.load is used to load a model file. Pickle files can execute arbitrary code during deserialization.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)pickle\s*\.\s*(?:load|loads)\s*\(""",
        "cwe_id": "CWE-502",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Use safetensors format instead of pickle. If pickle is required, use fickling to scan for malicious payloads. Use torch.load(..., weights_only=True).",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
        "file_types": [".py"],
    },
    {
        "id": "AI-MODEL-002",
        "category": "Insecure Model Loading",
        "title": "torch.load without weights_only=True",
        "description": "torch.load is called without weights_only=True, allowing arbitrary code execution via pickle deserialization.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""torch\s*\.\s*load\s*\([^)]*(?!weights_only\s*=\s*True)\)""",
        "cwe_id": "CWE-502",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Use torch.load(..., weights_only=True) or migrate to safetensors format.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
        "file_types": [".py"],
    },
    {
        "id": "AI-MODEL-003",
        "category": "Insecure Model Loading",
        "title": "joblib.load from User-Controlled Path",
        "description": "joblib.load is used with a potentially user-controlled file path, allowing arbitrary code execution.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)joblib\s*\.\s*load\s*\(\s*(?:request|input|user|path|filename|filepath|args|param)""",
        "cwe_id": "CWE-502",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Validate file paths against a whitelist. Only load models from trusted, verified sources.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
        "file_types": [".py"],
    },
    {
        "id": "AI-MODEL-004",
        "category": "Model Poisoning",
        "title": "Loading Model from Untrusted Source",
        "description": "A model is being loaded from a user-provided URL or untrusted repository without integrity verification.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:from_pretrained|load_model|download_model)\s*\(\s*(?:request|input|user|url|uri|args|param|f['"]|['"]?\s*\+)""",
        "cwe_id": "CWE-494",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Only load models from trusted sources. Verify model checksums/hashes before loading. Pin model versions.",
        "references": ["https://cwe.mitre.org/data/definitions/494.html"],
        "file_types": [".py"],
    },

    # ========================================================================
    # DATA LEAKAGE
    # ========================================================================
    {
        "id": "AI-LEAK-001",
        "category": "Data Leakage",
        "title": "Logging Prompts or Responses with PII",
        "description": "LLM prompts or responses are logged without PII filtering, potentially exposing sensitive user data.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:log(?:ger)?|print|console)\s*\.?\s*(?:info|debug|warning|error|log)?\s*\(\s*(?:f['"]{1,3}|['"]{1,3}\s*%\s*|['"]{1,3}\s*\.format\()?[^)]*(?:prompt|response|completion|message|chat_history|context|embedding)""",
        "cwe_id": "CWE-532",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Implement PII detection and redaction before logging. Use structured logging with sensitive field masking.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "AI-LEAK-002",
        "category": "Data Leakage",
        "title": "Training Data Contains PII Patterns",
        "description": "Training data or fine-tuning data may contain personally identifiable information (email, phone, SSN patterns).",
        "severity": "High",
        "confidence": "Low",
        "pattern": r"""(?i)(?:training_data|train_data|fine_tune|finetune|dataset)\s*(?:=|\[|\.)\s*[^;]*(?:email|phone|ssn|address|name|dob|birth|social_security)""",
        "cwe_id": "CWE-359",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Scrub PII from training data using NER-based redaction tools. Implement differential privacy.",
        "references": ["https://cwe.mitre.org/data/definitions/359.html"],
        "file_types": [".py", ".js"],
    },

    # ========================================================================
    # EXCESSIVE PERMISSIONS / AGENCY
    # ========================================================================
    {
        "id": "AI-PERM-001",
        "category": "Excessive Permissions",
        "title": "AI Agent with Unrestricted Tool Access",
        "description": "An AI agent is configured with tools that allow unrestricted actions (file system, database, code execution) without guardrails.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:tools|functions|plugins)\s*(?:=|:)\s*\[[\s\S]*?(?:exec|eval|subprocess|os\.system|shell|file_write|db_execute|sql_query|run_code|execute_code)""",
        "cwe_id": "CWE-250",
        "owasp": "LLM08:2025-Excessive Agency",
        "remediation": "Implement principle of least privilege for AI agents. Add confirmation prompts for destructive actions. Use sandboxed execution environments.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py", ".js", ".ts", ".yaml", ".yml"],
    },
    {
        "id": "AI-PERM-002",
        "category": "Excessive Permissions",
        "title": "AI Agent Can Execute Arbitrary Code",
        "description": "An AI agent has the ability to execute arbitrary code through eval(), exec(), or subprocess without sandboxing.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:exec|eval)\s*\(\s*(?:response|completion|output|result|llm|model|agent|generated|ai_)""",
        "cwe_id": "CWE-94",
        "owasp": "LLM08:2025-Excessive Agency",
        "remediation": "Never execute LLM-generated code directly. Use sandboxed environments (Docker, gVisor). Implement allow-lists for permitted operations.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
        "file_types": [".py"],
    },

    # ========================================================================
    # OUTPUT HANDLING
    # ========================================================================
    {
        "id": "AI-OUT-001",
        "category": "Insecure Output Handling",
        "title": "LLM Output Rendered as HTML",
        "description": "LLM-generated content is rendered as HTML without sanitization, enabling XSS attacks.",
        "severity": "High",
        "confidence": "High",
        "pattern": r"""(?i)(?:dangerouslySetInnerHTML|innerHTML|v-html)\s*(?:=|:)\s*(?:\{?\s*__html\s*:\s*)?(?:response|completion|output|result|answer|generated|ai_|llm_|model_)""",
        "cwe_id": "CWE-79",
        "owasp": "LLM02:2025-Insecure Output Handling",
        "remediation": "Sanitize LLM output before rendering. Use DOMPurify or equivalent. Render as plain text when possible.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
        "file_types": [".js", ".jsx", ".tsx", ".ts", ".vue", ".html"],
    },
    {
        "id": "AI-OUT-002",
        "category": "Insecure Output Handling",
        "title": "Executing LLM-Generated Code",
        "description": "Code generated by an LLM is executed without validation, allowing arbitrary code execution.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:exec|eval|subprocess\.(?:run|call|Popen))\s*\(\s*(?:.*\.)?(?:content|text|output|response|generated_code|code_output|completion)""",
        "cwe_id": "CWE-94",
        "owasp": "LLM02:2025-Insecure Output Handling",
        "remediation": "Never execute LLM-generated code directly. Use AST parsing and validation. Run in sandboxed environments.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
        "file_types": [".py"],
    },
    {
        "id": "AI-OUT-003",
        "category": "Insecure Output Handling",
        "title": "LLM Output Used in SQL Query",
        "description": "LLM-generated output is used in SQL query construction, enabling SQL injection.",
        "severity": "Critical",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:execute|cursor\.execute|query|raw_sql|text\()\s*\(\s*(?:f['""]|['""]?\s*\+\s*|['""]?\s*%\s*|['""][^'""]*\{)[^)]*(?:response|completion|output|generated|ai_|llm_|model_)""",
        "cwe_id": "CWE-89",
        "owasp": "LLM02:2025-Insecure Output Handling",
        "remediation": "Never use LLM output directly in SQL. Use parameterized queries. Validate and sanitize all LLM output.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "file_types": [".py", ".js", ".ts"],
    },

    # ========================================================================
    # EMBEDDING / RAG INJECTION
    # ========================================================================
    {
        "id": "AI-RAG-001",
        "category": "RAG Poisoning",
        "title": "Unvalidated Document Ingestion",
        "description": "Documents are ingested into a RAG pipeline without content validation or sanitization, allowing poisoning attacks.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:add_documents|add_texts|upsert|insert|ingest|load_documents?)\s*\(\s*(?:request|input|user|uploaded|files|documents)""",
        "cwe_id": "CWE-20",
        "owasp": "LLM03:2025-Training Data Poisoning",
        "remediation": "Validate and sanitize documents before ingestion. Implement content moderation. Use document provenance tracking.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "AI-RAG-002",
        "category": "Embedding Injection",
        "title": "User Input in Vector DB Query without Sanitization",
        "description": "User input is passed directly to vector database similarity search without sanitization, enabling embedding injection.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:similarity_search|query|search|retrieve|find_similar)\s*\(\s*(?:request|input|user_query|user_input|query|question)""",
        "cwe_id": "CWE-74",
        "owasp": "LLM01:2025-Prompt Injection",
        "remediation": "Sanitize user queries before vector search. Implement query length limits. Filter results for relevance.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py", ".js", ".ts"],
    },

    # ========================================================================
    # TOKEN / COST CONTROL
    # ========================================================================
    {
        "id": "AI-COST-001",
        "category": "Token/Cost Control",
        "title": "No max_tokens Limit Set",
        "description": "API call to LLM does not set max_tokens, allowing unbounded token usage and potential cost explosion.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:chat\.completions\.create|complete|generate|invoke)\s*\([^)]*(?!max_tokens|max_output_tokens|maxTokens)(?:\)\s*$|\)\s*[;,])""",
        "cwe_id": "CWE-770",
        "owasp": "LLM10:2025-Unbounded Consumption",
        "remediation": "Always set max_tokens/max_output_tokens to a reasonable limit. Implement per-user token budgets.",
        "references": ["https://cwe.mitre.org/data/definitions/770.html"],
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "AI-COST-002",
        "category": "Token/Cost Control",
        "title": "No Rate Limiting on AI API Calls",
        "description": "AI API endpoint has no rate limiting, allowing denial-of-wallet attacks.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)@(?:app\.(?:post|get)|router\.(?:post|get))\s*\(\s*['"]/[^'"]*(?:ai|llm|chat|complete|generate|predict)[^'"]*['"]\s*\)(?![\s\S]{0,200}(?:rate_limit|throttle|RateLimit|Throttle))""",
        "cwe_id": "CWE-770",
        "owasp": "LLM10:2025-Unbounded Consumption",
        "remediation": "Implement rate limiting on AI endpoints. Use token budgets per user. Set spending alerts.",
        "references": ["https://cwe.mitre.org/data/definitions/770.html"],
        "file_types": [".py", ".js", ".ts"],
    },

    # ========================================================================
    # SENSITIVE DATA IN CONTEXT
    # ========================================================================
    {
        "id": "AI-CTX-001",
        "category": "Sensitive Data in Context",
        "title": "Credentials Passed to LLM Context",
        "description": "Credentials, API keys, or secrets are being included in the LLM context window.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:messages|prompt|context|system_message)\s*(?:=|\.\s*append|\.format|\+)\s*[^;]*(?:password|secret|api_key|token|credential|private_key|access_key)""",
        "cwe_id": "CWE-200",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Never pass credentials or secrets to LLM context. Implement data masking before sending to LLM.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "AI-CTX-002",
        "category": "Sensitive Data in Context",
        "title": "PII in LLM Prompt",
        "description": "Personally identifiable information may be sent to the LLM without redaction.",
        "severity": "High",
        "confidence": "Low",
        "pattern": r"""(?i)(?:messages|prompt|context)\s*(?:=|\.\s*append|\.format|\+)\s*[^;]*(?:ssn|social_security|credit_card|card_number|date_of_birth|medical_record)""",
        "cwe_id": "CWE-359",
        "owasp": "LLM06:2025-Excessive Agency",
        "remediation": "Implement PII detection and redaction before sending data to LLMs. Use anonymization techniques.",
        "references": ["https://cwe.mitre.org/data/definitions/359.html"],
        "file_types": [".py", ".js", ".ts"],
    },

    # ========================================================================
    # MODEL ENDPOINT SECURITY
    # ========================================================================
    {
        "id": "AI-ENDP-001",
        "category": "Model Endpoint Security",
        "title": "Model Serving Endpoint without Authentication",
        "description": "A model serving endpoint (TensorFlow Serving, MLflow, FastAPI) lacks authentication.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)@(?:app\.(?:post|get)|router\.(?:post|get))\s*\(\s*['"]/(?:predict|inference|generate|embed|classify|v1/models)['"]\s*\)[\s\S]{0,100}(?:async\s+)?def\s+\w+\s*\(\s*(?!.*(?:auth|token|api_key|credentials|current_user|Depends))""",
        "cwe_id": "CWE-306",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Add authentication middleware to model serving endpoints. Use API keys or OAuth2.",
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
        "file_types": [".py"],
    },
    {
        "id": "AI-ENDP-002",
        "category": "Model Endpoint Security",
        "title": "MLflow/TensorFlow Serving with Debug Mode",
        "description": "A model serving configuration has debug mode enabled, potentially exposing model internals.",
        "severity": "Medium",
        "confidence": "High",
        "pattern": r"""(?i)(?:debug|DEBUG)\s*(?:=|:)\s*(?:True|true|1|"true"|'true')[\s\S]{0,200}(?:mlflow|tensorflow|torch|model|serving|inference)""",
        "cwe_id": "CWE-489",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Disable debug mode in production. Remove debug endpoints and verbose error messages.",
        "references": ["https://cwe.mitre.org/data/definitions/489.html"],
        "file_types": [".py", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"],
    },

    # ========================================================================
    # SUPPLY CHAIN
    # ========================================================================
    {
        "id": "AI-SUPPLY-001",
        "category": "Supply Chain",
        "title": "pip install from Unknown Model Repository",
        "description": "Dependencies are installed from unknown or untrusted model repositories.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)pip\s+install\s+(?:--index-url|--extra-index-url|-i)\s+(?!https://pypi\.org)""",
        "cwe_id": "CWE-494",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Only install packages from trusted repositories. Pin versions and verify checksums.",
        "references": ["https://cwe.mitre.org/data/definitions/494.html"],
        "file_types": [".py", ".sh", ".bash", ".yml", ".yaml", ".txt"],
    },
    {
        "id": "AI-SUPPLY-002",
        "category": "Supply Chain",
        "title": "HuggingFace Model Download without Verification",
        "description": "A model is downloaded from HuggingFace without hash/checksum verification.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:from_pretrained|hf_hub_download|snapshot_download)\s*\(\s*['"][^'"]+['"](?![\s\S]*(?:revision|hash|checksum|verify))""",
        "cwe_id": "CWE-494",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Pin model versions using revision parameter. Verify model hashes. Use private model registries.",
        "references": ["https://cwe.mitre.org/data/definitions/494.html"],
        "file_types": [".py"],
    },

    # ========================================================================
    # TRAINING DATA SECURITY
    # ========================================================================
    {
        "id": "AI-TRAIN-001",
        "category": "Training Data Security",
        "title": "World-Readable Model File Permissions",
        "description": "Model files are saved with world-readable permissions, exposing proprietary model weights.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:save_pretrained|save_model|torch\.save|joblib\.dump|pickle\.dump)\s*\(\s*[^)]*['"]/(?:tmp|var|public|www|static|uploads)""",
        "cwe_id": "CWE-276",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Save model files with restricted permissions (600 or 640). Use encrypted storage for proprietary models.",
        "references": ["https://cwe.mitre.org/data/definitions/276.html"],
        "file_types": [".py"],
    },
    {
        "id": "AI-TRAIN-002",
        "category": "Training Data Security",
        "title": "Unencrypted Training Data Storage",
        "description": "Training data is stored without encryption, potentially exposing sensitive data used for model training.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:to_csv|to_json|to_parquet|save_to_disk)\s*\(\s*['"]/[^'"]*(?:training|train|dataset|data)[^'"]*['"](?![\s\S]*encrypt)""",
        "cwe_id": "CWE-311",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Encrypt training data at rest. Use encrypted file systems or dataset encryption libraries.",
        "references": ["https://cwe.mitre.org/data/definitions/311.html"],
        "file_types": [".py"],
    },

    # ========================================================================
    # LANGCHAIN-SPECIFIC
    # ========================================================================
    {
        "id": "AI-LC-001",
        "category": "LangChain Security",
        "title": "SQLDatabaseChain without Input Validation",
        "description": "LangChain SQLDatabaseChain is used without input validation, allowing SQL injection via natural language.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)SQLDatabase(?:Chain|SequentialChain|Toolkit)\s*(?:\.\s*from_llm|\()""",
        "cwe_id": "CWE-89",
        "owasp": "LLM02:2025-Insecure Output Handling",
        "remediation": "Use read-only database connections. Implement query validation and allow-lists. Restrict accessible tables.",
        "references": ["https://python.langchain.com/docs/security/"],
        "file_types": [".py"],
    },
    {
        "id": "AI-LC-002",
        "category": "LangChain Security",
        "title": "PythonREPLTool Enabled",
        "description": "LangChain PythonREPLTool allows the LLM to execute arbitrary Python code.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)PythonREPL(?:Tool)?\s*\(""",
        "cwe_id": "CWE-94",
        "owasp": "LLM08:2025-Excessive Agency",
        "remediation": "Avoid PythonREPLTool in production. Use sandboxed code execution environments. Implement code validation.",
        "references": ["https://python.langchain.com/docs/security/"],
        "file_types": [".py"],
    },
    {
        "id": "AI-LC-003",
        "category": "LangChain Security",
        "title": "LLMChain with Unrestricted Output Parsing",
        "description": "LangChain chain output is used directly without validation or output parsing restrictions.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:LLMChain|ConversationalChain|RetrievalQA)\s*\([^)]*\)\s*\.(?:run|invoke|predict)\s*\(""",
        "cwe_id": "CWE-20",
        "owasp": "LLM02:2025-Insecure Output Handling",
        "remediation": "Validate chain outputs. Use output parsers with strict schemas. Implement output filtering.",
        "references": ["https://python.langchain.com/docs/security/"],
        "file_types": [".py"],
    },

    # ========================================================================
    # OPENAI-SPECIFIC
    # ========================================================================
    {
        "id": "AI-OAI-001",
        "category": "OpenAI Security",
        "title": "Function Calling without Input Validation",
        "description": "OpenAI function calling is configured without validating function arguments from the model.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:function_call|tool_choice)\s*(?:=|:)\s*(?:"auto"|'auto'|"required"|'required')[\s\S]{0,300}(?!validate|sanitize|check|verify)(?:call|execute|invoke|run)\s*\(""",
        "cwe_id": "CWE-20",
        "owasp": "LLM08:2025-Excessive Agency",
        "remediation": "Always validate function call arguments from the model. Implement strict parameter schemas. Add confirmation steps.",
        "references": ["https://platform.openai.com/docs/guides/function-calling"],
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "AI-OAI-002",
        "category": "OpenAI Security",
        "title": "Missing Content Moderation",
        "description": "Content is sent to or received from OpenAI without moderation checks.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:chat\.completions\.create|openai\.(?:Completion|ChatCompletion))\s*\([^)]*\)(?![\s\S]{0,300}(?:moderat|filter|content_policy|safety_check))""",
        "cwe_id": "CWE-20",
        "owasp": "LLM02:2025-Insecure Output Handling",
        "remediation": "Use OpenAI's moderation endpoint to check inputs and outputs. Implement content filtering.",
        "references": ["https://platform.openai.com/docs/guides/moderation"],
        "file_types": [".py", ".js", ".ts"],
    },

    # ========================================================================
    # HUGGINGFACE-SPECIFIC
    # ========================================================================
    {
        "id": "AI-HF-001",
        "category": "HuggingFace Security",
        "title": "Pipeline with User-Controlled Model Name",
        "description": "HuggingFace transformers pipeline loads a model from a user-controlled variable, enabling supply chain attacks.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)pipeline\s*\(\s*[^)]*model\s*=\s*(?:request|input|user|args|param|form)""",
        "cwe_id": "CWE-494",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Use a whitelist of allowed model names. Never let users specify arbitrary model identifiers.",
        "references": ["https://huggingface.co/docs/hub/security"],
        "file_types": [".py"],
    },
    {
        "id": "AI-HF-002",
        "category": "HuggingFace Security",
        "title": "AutoModel with trust_remote_code=True",
        "description": "AutoModel.from_pretrained uses trust_remote_code=True, allowing execution of arbitrary code from model repos.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:Auto(?:Model|Tokenizer|Config|FeatureExtractor)|from_pretrained)\s*[.(][^)]*trust_remote_code\s*=\s*True""",
        "cwe_id": "CWE-94",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Avoid trust_remote_code=True. Audit remote code before enabling. Use locally verified model code.",
        "references": ["https://huggingface.co/docs/hub/security"],
        "file_types": [".py"],
    },

    # ========================================================================
    # VECTOR DB SECURITY
    # ========================================================================
    {
        "id": "AI-VDB-001",
        "category": "Vector DB Security",
        "title": "Vector Database without Authentication",
        "description": "Vector database client (Pinecone, Weaviate, Chroma, Milvus) is initialized without authentication.",
        "severity": "High",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:Pinecone|Weaviate|Chroma|Milvus|Qdrant|FAISS)(?:Client|\.init|\.connect|\()\s*\([^)]*(?!api_key|auth|token|password|credentials)[^)]*\)""",
        "cwe_id": "CWE-306",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Configure authentication for vector database connections. Use API keys or mutual TLS.",
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "AI-VDB-002",
        "category": "Vector DB Security",
        "title": "Chroma/FAISS with Persistent Local Storage",
        "description": "Vector database uses persistent local storage without access controls or encryption.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:Chroma|FAISS)\s*\.\s*(?:from_documents|from_texts)\s*\([^)]*persist_directory\s*=\s*['"]""",
        "cwe_id": "CWE-276",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Set proper file permissions on persistent storage directories. Consider encrypting the vector store.",
        "references": ["https://cwe.mitre.org/data/definitions/276.html"],
        "file_types": [".py"],
    },

    # ========================================================================
    # AI CONFIG FILES
    # ========================================================================
    {
        "id": "AI-CFG-001",
        "category": "AI Configuration",
        "title": "Model Serving Config with Debug Enabled",
        "description": "A model serving configuration file has debug mode enabled, exposing metrics and internals.",
        "severity": "Medium",
        "confidence": "High",
        "pattern": r"""(?i)(?:debug|DEBUG|verbose|VERBOSE)\s*(?:=|:)\s*(?:true|True|1|"true"|'true'|on|yes)""",
        "cwe_id": "CWE-489",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Disable debug mode in production configurations.",
        "references": ["https://cwe.mitre.org/data/definitions/489.html"],
        "file_types": [".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf"],
    },
    {
        "id": "AI-CFG-002",
        "category": "AI Configuration",
        "title": "Exposed Metrics/Monitoring Endpoint",
        "description": "Model serving metrics or monitoring endpoint is exposed without authentication.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:metrics|prometheus|grafana|health|status)[._]?(?:port|endpoint|url|host)\s*(?:=|:)\s*(?:['"]0\.0\.0\.0|['"][:]*[0-9]+)""",
        "cwe_id": "CWE-200",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Protect metrics endpoints with authentication. Bind to localhost or internal network only.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
        "file_types": [".yaml", ".yml", ".json", ".toml", ".py"],
    },

    # ========================================================================
    # INFERENCE MANIPULATION
    # ========================================================================
    {
        "id": "AI-INFER-001",
        "category": "Inference Manipulation",
        "title": "No Output Validation on Model Predictions",
        "description": "Model predictions are used directly for security-sensitive decisions without validation.",
        "severity": "High",
        "confidence": "Low",
        "pattern": r"""(?i)(?:predict|inference|classify|detect)\s*\([^)]*\)\s*[\s\S]{0,100}(?:if|access|allow|deny|grant|authorize|authenticate)""",
        "cwe_id": "CWE-20",
        "owasp": "LLM09:2025-Misinformation",
        "remediation": "Never use model predictions as the sole basis for security decisions. Add confidence thresholds and human review.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py", ".js", ".ts"],
    },

    # ========================================================================
    # RLHF / REWARD HACKING
    # ========================================================================
    {
        "id": "AI-RLHF-001",
        "category": "RLHF Security",
        "title": "Reward Model without Robustness Checks",
        "description": "RLHF reward model is used without adversarial robustness testing, enabling reward hacking.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:reward_model|RewardModel|PPOTrainer|DPOTrainer)\s*\((?![\s\S]*(?:adversarial|robust|safety_check|constraint))""",
        "cwe_id": "CWE-693",
        "owasp": "LLM09:2025-Misinformation",
        "remediation": "Implement reward model robustness testing. Use constitutional AI constraints. Add safety reward terms.",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "file_types": [".py"],
    },

    # ========================================================================
    # MODEL VERSIONING
    # ========================================================================
    {
        "id": "AI-VER-001",
        "category": "Model Versioning",
        "title": "Model Download without Integrity Check",
        "description": "Model files are downloaded without hash verification, enabling model tampering.",
        "severity": "Medium",
        "confidence": "Medium",
        "pattern": r"""(?i)(?:urllib\.request\.urlretrieve|requests\.get|wget|curl)\s*\([^)]*(?:model|weights|checkpoint)[^)]*\)(?![\s\S]*(?:hash|checksum|sha256|md5|verify|integrity))""",
        "cwe_id": "CWE-494",
        "owasp": "LLM05:2025-Supply Chain Vulnerabilities",
        "remediation": "Always verify model file integrity after download using SHA-256 checksums.",
        "references": ["https://cwe.mitre.org/data/definitions/494.html"],
        "file_types": [".py", ".sh"],
    },

    # ========================================================================
    # FEATURE STORE
    # ========================================================================
    {
        "id": "AI-FEAT-001",
        "category": "Feature Store Security",
        "title": "Feature Store without Access Control",
        "description": "Feature store (Feast, Tecton, Hopsworks) is accessed without authentication or authorization checks.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:FeatureStore|feast\.FeatureStore|Tecton|Hopsworks)\s*\(\s*(?!.*(?:auth|token|credentials|api_key))""",
        "cwe_id": "CWE-306",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Configure authentication for feature store access. Implement RBAC for feature access.",
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
        "file_types": [".py"],
    },

    # ========================================================================
    # JUPYTER NOTEBOOK SECRETS
    # ========================================================================
    {
        "id": "AI-JNB-001",
        "category": "Jupyter Notebook Security",
        "title": "API Key in Jupyter Notebook",
        "description": "An API key or secret is hardcoded in a Jupyter notebook cell, which is often committed to version control.",
        "severity": "Critical",
        "confidence": "High",
        "pattern": r"""(?i)(?:api_key|secret_key|access_token|password)\s*=\s*['"](sk-|hf_|ghp_|gho_|Bearer\s+)[^'"]{10,}['"]""",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Use environment variables or .env files for secrets. Add .ipynb to .gitignore or use nbstripout.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "file_types": [".ipynb", ".py"],
    },
    {
        "id": "AI-JNB-002",
        "category": "Jupyter Notebook Security",
        "title": "Notebook with Cell Outputs Containing Secrets",
        "description": "Jupyter notebook cell outputs may contain API keys, tokens, or credentials that were printed during execution.",
        "severity": "High",
        "confidence": "Low",
        "pattern": r"""(?i)(?:print|display)\s*\(\s*(?:.*(?:api_key|token|secret|password|credential))""",
        "cwe_id": "CWE-532",
        "owasp": "A09:2021-Security Logging and Monitoring Failures",
        "remediation": "Clear notebook outputs before committing. Use nbstripout as a git filter.",
        "references": ["https://cwe.mitre.org/data/definitions/532.html"],
        "file_types": [".ipynb", ".py"],
    },

    # ========================================================================
    # ADVERSARIAL INPUT
    # ========================================================================
    {
        "id": "AI-ADV-001",
        "category": "Adversarial Input",
        "title": "No Input Validation for Model Inference",
        "description": "Model inference endpoint accepts input without validation, enabling adversarial attacks.",
        "severity": "Medium",
        "confidence": "Low",
        "pattern": r"""(?i)(?:model\.predict|model\.forward|model\(|inference)\s*\(\s*(?:request\.(?:json|data|body|form)|input_data|raw_input)(?![\s\S]{0,100}(?:validate|sanitize|check|clip|normalize|preprocess))""",
        "cwe_id": "CWE-20",
        "owasp": "LLM01:2025-Prompt Injection",
        "remediation": "Validate and preprocess inputs before inference. Implement input bounds checking and type validation.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
        "file_types": [".py"],
    },
]


# ---------------------------------------------------------------------------
# Semantic Analyzer for AI/LLM patterns
# ---------------------------------------------------------------------------
class AILLMSemanticAnalyzer:
    """Performs deeper semantic analysis on AI/LLM code."""

    def analyze(self, content: str, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split('\n')

        self._check_env_file_secrets(content, lines, filepath, findings)
        self._check_config_file_issues(content, lines, filepath, findings)
        self._check_requirements_vulnerabilities(content, lines, filepath, findings)

        return findings

    def _check_env_file_secrets(self, content: str, lines: List[str],
                                 filepath: str, findings: List[Finding]):
        """Check .env files for AI-related secrets."""
        if not filepath.endswith('.env'):
            return

        ai_key_patterns = [
            (r"OPENAI_API_KEY\s*=\s*sk-[a-zA-Z0-9_-]{20,}", "OpenAI API Key"),
            (r"ANTHROPIC_API_KEY\s*=\s*sk-ant-[a-zA-Z0-9_-]{20,}", "Anthropic API Key"),
            (r"HUGGINGFACE_TOKEN\s*=\s*hf_[a-zA-Z0-9]{20,}", "HuggingFace Token"),
            (r"COHERE_API_KEY\s*=\s*[a-zA-Z0-9]{30,}", "Cohere API Key"),
            (r"PINECONE_API_KEY\s*=\s*[a-zA-Z0-9_-]{30,}", "Pinecone API Key"),
            (r"WANDB_API_KEY\s*=\s*[a-zA-Z0-9]{30,}", "Weights & Biases API Key"),
            (r"REPLICATE_API_TOKEN\s*=\s*r8_[a-zA-Z0-9]{30,}", "Replicate API Token"),
        ]

        for pattern_str, key_name in ai_key_patterns:
            pattern = re.compile(pattern_str)
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id="AI-ENV-001",
                        category="API Key Exposure",
                        title=f"{key_name} in .env File",
                        description=f"A {key_name} is stored in a .env file. Ensure this file is in .gitignore.",
                        severity="High",
                        confidence="High",
                        file_path=filepath,
                        line_number=i,
                        code_snippet=line.strip()[:50] + "...",
                        remediation="Use a secrets manager. Ensure .env is in .gitignore. Rotate exposed keys immediately.",
                        cwe_id="CWE-798",
                        owasp="A07:2021-Identification and Authentication Failures",
                    ))

    def _check_config_file_issues(self, content: str, lines: List[str],
                                    filepath: str, findings: List[Finding]):
        """Check AI config files (YAML, JSON, TOML) for security issues."""
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in ('.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf'):
            return

        # Check for model serving configs with exposed ports
        if re.search(r'(?i)(?:host|bind)\s*(?:=|:)\s*[\'"]?0\.0\.0\.0', content):
            if re.search(r'(?i)(?:model|inference|predict|serve|ml)', content):
                line_num = 1
                for i, line in enumerate(lines, 1):
                    if re.search(r'(?i)(?:host|bind)\s*(?:=|:)\s*[\'"]?0\.0\.0\.0', line):
                        line_num = i
                        break
                findings.append(Finding(
                    rule_id="AI-CFG-003",
                    category="AI Configuration",
                    title="Model Server Bound to All Interfaces",
                    description="Model serving endpoint is bound to 0.0.0.0, making it accessible from all network interfaces.",
                    severity="Medium",
                    confidence="Medium",
                    file_path=filepath,
                    line_number=line_num,
                    code_snippet=lines[line_num-1].strip() if line_num <= len(lines) else "",
                    remediation="Bind model serving to localhost (127.0.0.1) or internal network interface. Use a reverse proxy for external access.",
                    cwe_id="CWE-668",
                    owasp="A05:2021-Security Misconfiguration",
                ))

    def _check_requirements_vulnerabilities(self, content: str, lines: List[str],
                                              filepath: str, findings: List[Finding]):
        """Check requirements files for known vulnerable AI/ML packages."""
        basename = os.path.basename(filepath).lower()
        if basename not in ('requirements.txt', 'setup.py', 'pyproject.toml', 'pipfile'):
            return

        vulnerable_patterns = [
            (r"(?i)transformers\s*[<>=!]*\s*(?:3\.|4\.0|4\.1[0-9]\.0)", "transformers", "Update to latest version for security fixes"),
            (r"(?i)langchain\s*[<>=!]*\s*0\.0\.[0-9]{1,2}[^0-9]", "langchain", "Update to latest version (>=0.1.0) for security patches"),
            (r"(?i)openai\s*[<>=!]*\s*0\.[0-9]", "openai", "Update to openai>=1.0 for security improvements"),
            (r"(?i)torch\s*[<>=!]*\s*(?:1\.[0-9]|1\.1[0-2])", "PyTorch", "Update PyTorch for security patches"),
        ]

        for pattern_str, pkg_name, fix in vulnerable_patterns:
            pattern = re.compile(pattern_str)
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id="AI-DEP-001",
                        category="Supply Chain",
                        title=f"Outdated {pkg_name} Version",
                        description=f"An outdated version of {pkg_name} is specified, which may contain known vulnerabilities.",
                        severity="Medium",
                        confidence="Medium",
                        file_path=filepath,
                        line_number=i,
                        code_snippet=line.strip(),
                        remediation=fix,
                        cwe_id="CWE-1104",
                        owasp="LLM05:2025-Supply Chain Vulnerabilities",
                    ))


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings."""
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in findings:
        key = f"{f.file_path}:{f.line_number}:{f.rule_id}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------
class AILLMScanner:
    """Orchestrates scanning for AI/LLM security issues."""

    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".vue",
        ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf",
        ".env", ".sh", ".bash", ".txt", ".ipynb",
    }

    def __init__(self):
        self.semantic_analyzer = AILLMSemanticAnalyzer()
        log.info("AI/LLM Scanner initialized")

    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet around the given line."""
        start = max(0, line_num - 1 - context)
        end = min(len(lines), line_num + context)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{marker} {i+1:4d} | {lines[i]}")
        return '\n'.join(snippet_lines)

    def _should_apply_rule(self, rule: Dict, filepath: str) -> bool:
        """Check if a rule should be applied to the given file type."""
        file_types = rule.get("file_types", [])
        if not file_types:
            return True
        ext = os.path.splitext(filepath)[1].lower()
        # Special handling for .env files
        basename = os.path.basename(filepath).lower()
        if '.env' in file_types and basename.startswith('.env'):
            return True
        return ext in file_types

    def _apply_regex_rules(self, content: str, filepath: str) -> List[Finding]:
        """Apply all regex-based vulnerability rules."""
        findings: List[Finding] = []
        lines = content.split('\n')

        for rule in AI_LLM_RULES:
            if not self._should_apply_rule(rule, filepath):
                continue

            try:
                pattern = re.compile(rule["pattern"], re.MULTILINE)
                for m in pattern.finditer(content):
                    line_num = content[:m.start()].count('\n') + 1
                    snippet = self._get_snippet(lines, line_num)

                    findings.append(Finding(
                        rule_id=rule["id"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=snippet,
                        remediation=rule["remediation"],
                        cwe_id=rule["cwe_id"],
                        owasp=rule["owasp"],
                        references=rule.get("references", []),
                    ))
            except re.error as e:
                log.warning(f"Regex error for rule {rule['id']}: {e}")

        return findings

    def _handle_ipynb(self, content: str, filepath: str) -> Dict[str, str]:
        """Extract code cells from Jupyter notebooks for scanning."""
        extracted: Dict[str, str] = {}
        try:
            notebook = json.loads(content)
            cells = notebook.get('cells', [])
            for idx, cell in enumerate(cells):
                if cell.get('cell_type') == 'code':
                    source = ''.join(cell.get('source', []))
                    cell_path = f"{filepath}#cell_{idx}"
                    extracted[cell_path] = source
        except (json.JSONDecodeError, KeyError):
            pass
        return extracted

    def scan(self, files: Dict[str, str], scan_id: str) -> ScanResponse:
        """Scan all provided files and return findings."""
        all_findings: List[Finding] = []
        scanned = 0

        # Expand .ipynb files into individual cells
        expanded_files: Dict[str, str] = {}
        for path, content in files.items():
            ext = os.path.splitext(path)[1].lower()
            if ext not in self.SUPPORTED_EXTENSIONS:
                # Also check basename for dotfiles like .env
                basename = os.path.basename(path).lower()
                if not basename.startswith('.env'):
                    continue

            if ext == '.ipynb':
                cells = self._handle_ipynb(content, path)
                expanded_files.update(cells)
                # Also scan the raw notebook content
                expanded_files[path] = content
            else:
                expanded_files[path] = content

        for path, content in expanded_files.items():
            scanned += 1

            # Phase 1: Regex-based rules
            regex_findings = self._apply_regex_rules(content, path)
            all_findings.extend(regex_findings)

            # Phase 2: Semantic analysis
            try:
                semantic_findings = self.semantic_analyzer.analyze(content, path)
                all_findings.extend(semantic_findings)
            except Exception as e:
                log.warning(f"Semantic analysis failed for {path}: {e}")

        # Deduplicate
        all_findings = deduplicate_findings(all_findings)

        # Sort by severity then file/line
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.file_path, f.line_number))

        # Build summary
        summary: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in all_findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        return ScanResponse(
            scanId=scan_id or str(uuid.uuid4()),
            totalFiles=scanned,
            totalFindings=len(all_findings),
            findings=[asdict(f) for f in all_findings],
            summary=summary,
        )


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Offensive360 AI/LLM Technology SAST Scanner",
    description="Comprehensive static analysis for AI/ML/LLM applications - detects prompt injection, API key exposure, insecure model loading, and more",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = AILLMScanner()


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "scanner": "AI/LLM Technology SAST Scanner",
        "version": "1.0.0",
        "engine": "regex + semantic analysis",
        "vulnerability_categories": 25,
        "total_rules": len(AI_LLM_RULES) + 10,  # regex + semantic rules
        "supported_frameworks": [
            "OpenAI", "Anthropic", "HuggingFace", "LangChain",
            "PyTorch", "TensorFlow", "Pinecone", "Weaviate",
            "Chroma", "MLflow", "Feast", "FAISS",
        ],
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_files(request: ScanRequest):
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided")
    log.info(f"Scan request received: {len(request.files)} files, scanId={request.scanId}")
    try:
        result = scanner.scan(request.files, request.scanId)
        log.info(f"Scan complete: {result.totalFindings} findings in {result.totalFiles} files")
        return result
    except Exception as e:
        log.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("SCANNER_PORT", "9021"))
    log.info(f"Starting AI/LLM Technology SAST Scanner on port {port}")
    log.info(f"Rules: {len(AI_LLM_RULES)} regex + 10 semantic = {len(AI_LLM_RULES) + 10} total")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
