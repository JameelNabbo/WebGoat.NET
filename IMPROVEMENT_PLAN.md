# SAST Offline Scanner Platform - Improvement Plan

## Current Status (March 9, 2026)

### Platform Stats
- **21 scanners** covering 21 languages, all running as microservices
- **44,000+ lines** of scanner code, **88,000+ total lines**
- **460 vulnerabilities** found across 11 real-world vulnerable projects (1,079 files)
- **Test Suite**: 100/103 tests passing
- **AI Verification**: 73 findings verified by Claude AI

### AI Verification Results (Claude Sonnet)
| Metric | Count | Percentage |
|--------|-------|-----------|
| True Positives | 30 | 41.1% |
| False Positives | 15 | 20.5% |
| Uncertain | 28 | 38.4% |

### Per-Scanner False Positive Rates
| Scanner | Verified | TP | FP | FP Rate |
|---------|----------|----|----|---------|
| Ruby | 10 | 8 | 2 | 20.0% |
| Python | 13 | 9 | 4 | 30.8% |
| JavaScript | 20 | 6 | 6 | 30.0% |
| PHP | 10 | 7 | 3 | 30.0% |
| C# | 10 | 0 | 0 | 0.0% (all uncertain) |
| Go | 10 | 0 | 0 | 0.0% (all uncertain) |

### High FP Categories (Need Improvement)
- Insecure Random: 100% FP - being too aggressive
- SSRF: 100% FP - not checking if URL is user-controlled
- Code Injection: 100% FP - flagging non-dangerous eval patterns
- Hardcoded Secrets: 29% FP - flagging example/test values

### Real Project Scan Results
| Project | Language | Files | Vulns Found |
|---------|----------|-------|-------------|
| DVWA | PHP | 167 | 278 |
| railsgoat | Ruby | 142 | 64 |
| vuln-nodejs-app | JS | 19 | 39 |
| Vulnerable-Flask-App | Python | 2 | 24 |
| govwa | Go | 20 | 21 |
| WebGoat.Net | C# | 150 | 17 |
| vulnerable-node | JS | 13 | 14 |
| dvpwa | Python | 16 | 3 |
| **WebGoat (Java)** | **Java** | **400** | **0** ⚠️ |
| **JavaVulnerableLab** | **Java** | **60** | **0** ⚠️ |

---

## Priority 1: Critical Fixes (Immediate)

### 1.1 Fix Java Scanner Cross-File Analysis
**Problem**: Java scanner found 0 vulnerabilities in WebGoat (400 files) and JavaVulnerableLab (60 files). It works for single-file analysis but fails on real Spring Boot projects where taint flows cross multiple classes via DI.
**Fix**: Implement inter-file taint tracking - build a call graph across all files, resolve Spring annotations (@RequestMapping, @Controller, @Service), and track data flow through dependency injection.
**Impact**: HIGH - Java is a top enterprise language

### 1.2 Reduce Insecure Random False Positives
**Problem**: 100% FP rate on "Insecure Random" category
**Fix**: Only flag `random`/`Math.random`/`rand()` when the result is used in security-critical contexts (tokens, passwords, crypto keys, session IDs). Don't flag game logic, UI, or test code.

### 1.3 Reduce SSRF False Positives
**Problem**: 100% FP rate - flagging all HTTP client calls
**Fix**: Implement proper taint tracking - only flag when the URL parameter traces back to user input (request params, form data, headers). Internal hardcoded URLs are safe.

### 1.4 Fix Code Injection False Positives
**Problem**: Flagging safe eval() patterns (constant strings, config loading)
**Fix**: Check if the argument to eval/exec is a constant/literal string or traces to user input. Only flag when taint analysis shows user-controllable data.

### 1.5 Improve Hardcoded Secrets Detection
**Problem**: 29% FP rate - flagging example values and test data
**Fix**:
- Skip files in test/spec/example directories
- Recognize AWS example key (AKIAIOSFODNN7EXAMPLE)
- Use entropy analysis - real secrets have high entropy
- Check if value matches known placeholder patterns

### 1.6 Fix 3 Failing Tests
- Java command injection detection test
- Go scanner false positive on safe code
- C# XSS detection test

---

## Priority 2: Missing Languages (Short-term)

### 2.1 R Language Scanner (Port 9022)
- Data science/biotech/finance market
- SQL injection in dbGetQuery(), path traversal, credential exposure
- Frameworks: Shiny, Plumber API

### 2.2 PowerShell Scanner (Port 9023)
- Windows enterprise administration, Azure automation
- Command injection, credential exposure, insecure modules
- Critical for enterprise customers

### 2.3 Elixir/Erlang Scanner (Port 9024)
- Growing real-time systems (Discord, WhatsApp)
- Phoenix framework security, ETS/Mnesia data exposure
- No major commercial SAST covers it

### 2.4 COBOL Scanner (Port 9025)
- 43% of banking systems, 95% of ATM transactions
- Fortify, Veracode, Checkmarx all support it
- Enterprise/government requirement

### 2.5 Solidity Scanner (Port 9026)
- Smart contract security, billions in locked value
- Reentrancy, integer overflow, access control
- Differentiator over most competitors

### 2.6 Lua Scanner (Port 9027)
- Game engines, IoT firmware, Redis scripting
- Injection, privilege escalation, sandbox escape

### 2.7 ABAP Scanner (Port 9028)
- SAP proprietary language, enterprise requirement
- SQL injection, authorization bypass

### 2.8 Haskell Scanner (Port 9029)
- Fintech (Standard Chartered, Barclays), blockchain (Cardano)

---

## Priority 3: Missing Vulnerability Categories (Per Scanner)

### 3.1 ALL Scanners - Add These Universal Categories
- **SSRF** (with proper taint tracking)
- **Insecure Deserialization** (language-specific sinks)
- **CSRF Detection** (framework-specific)
- **Missing Authorization** (decorator/middleware checks)
- **IDOR** (user-controlled ID without ownership check)
- **File Upload** (type validation, size limits)
- **GraphQL Injection** (introspection, depth attacks)
- **WebSocket Security** (auth, origin validation)
- **Supply Chain** (dependency confusion, typosquatting)
- **SBOM Generation** (CycloneDX/SPDX output)

### 3.2 OWASP Top 10:2025 Gaps
- **A06 Insecure Design**: Rate limiting absence, anti-automation missing, business logic flaws
- **A09 Security Logging Failures**: Missing security event logging, PII in logs
- **A10 Mishandling Exceptional Conditions**: NEW in 2025 - failing open, info leakage in errors

### 3.3 OWASP API Security Top 10:2023
- BOLA (Broken Object Level Authorization)
- Unrestricted Resource Consumption (rate limiting)
- Broken Function Level Authorization

### 3.4 OWASP Mobile Top 10:2024
- Certificate pinning absence
- Insecure data storage (SharedPreferences/NSUserDefaults)
- Missing binary protections
- Privacy manifest compliance (iOS)

### 3.5 OWASP LLM Top 10:2025
- Prompt injection patterns
- Sensitive data in LLM context
- Excessive agency (unrestricted tool calling)
- System prompt leakage

---

## Priority 4: Framework Coverage Gaps

### Python - Add:
- Tornado, Pyramid, Starlette, Sanic, aiohttp
- Celery task queue injection
- SQLAlchemy ORM injection patterns

### JavaScript/TypeScript - Add:
- NestJS, Fastify, Nuxt.js, SvelteKit, Remix
- Electron desktop app security (nodeIntegration, IPC)
- React Native mobile security
- GraphQL (Apollo, Yoga) specific rules
- Prisma ORM injection

### Java - Add:
- Quarkus, Micronaut, Jakarta EE, Vert.x
- JNDI injection (Log4Shell patterns)
- Thymeleaf/Freemarker SSTI
- MyBatis ORM injection
- Apache Camel, Kafka consumers

### C# - Add:
- Blazor (Server/WASM) security
- MAUI (.NET mobile)
- Minimal APIs pattern
- BinaryFormatter deserialization
- Dapper ORM injection

### PHP - Add:
- Drupal, Magento, Yii, CakePHP
- Twig SSTI patterns
- preg_replace /e modifier

### Go - Add:
- Chi, Gorilla, Beego, Buffalo
- GORM ORM injection
- text/template vs html/template

### IaC - Add:
- AWS CloudFormation
- Azure ARM/Bicep templates
- Ansible playbooks
- Helm charts
- Pulumi

---

## Priority 5: Architecture Improvements

### 5.1 Secrets Scanner (Dedicated Service)
- 170+ secret type detection (AWS, GCP, Azure, Stripe, etc.)
- Entropy-based detection for obfuscated secrets
- .env file scanning
- Git history scanning

### 5.2 SBOM Generator
- CycloneDX format output
- SPDX format output
- Dependency tree analysis
- License compliance checking

### 5.3 Inter-File Taint Analysis Engine
- Cross-file data flow tracking
- Framework-aware DI resolution
- Call graph construction
- Import/require chain following

### 5.4 Confidence Score Improvements
- Multi-factor scoring: detection method + data flow depth + framework context
- Reduce FP rate from 20.5% to <10%
- AI-assisted verification integration

### 5.5 Performance Optimizations
- File-level parallelism within each scanner
- Rule batching in single AST walk
- Incremental scanning (cache AST, rescan changed files)
- Pre-grep filtering to skip irrelevant files

### 5.6 Systemd Services for Auto-Restart
- Create systemd unit files for all scanners
- Auto-restart on failure
- Health check monitoring

### 5.7 Docker Containerization
- Dockerfile per scanner
- docker-compose.yml for full platform
- Resource limits per container

---

## Priority 6: UI Improvements

### 6.1 Current Bugs Fixed
- ✅ owaspList.map TypeError (string vs array handling)

### 6.2 New UI Features
- SARIF export format (IDE integration standard)
- PDF report generation
- Trend analysis across multiple scans
- Diff view (compare two scans)
- Inline code editor for reviewing findings
- Vulnerability grouping by file/category
- Suppression/false-positive marking
- Dashboard with historical scan statistics

---

## Competitive Comparison

| Capability | Checkmarx | Fortify | Our Platform | Gap |
|------------|-----------|---------|-------------|-----|
| Languages | 35+ | 44+ | 21 | Need 10+ more |
| FP Rate | ~15% | ~20% | 20.5% | Need to reduce |
| SBOM | Yes | Yes | No | Priority 5.2 |
| Secrets | 170+ types | Yes | Limited | Priority 5.1 |
| SSTI | Yes | Yes | Partial | Priority 3.1 |
| GraphQL | Yes | Limited | No | Priority 3.1 |
| AI Fix | AI-assisted | Yes | Yes ✅ | Differentiator |
| Offline | No | No | Yes ✅ | Key differentiator |

---

## Timeline Estimate

| Phase | Items | Timeframe |
|-------|-------|-----------|
| Priority 1 | Critical fixes, reduce FP rate | 1-2 weeks |
| Priority 2 | 8 new language scanners | 3-4 weeks |
| Priority 3 | Missing vuln categories | 2-3 weeks |
| Priority 4 | Framework coverage | 2-3 weeks |
| Priority 5 | Architecture improvements | 3-4 weeks |
| Priority 6 | UI improvements | 1-2 weeks |
