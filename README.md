# Security Automation Toolkit

[![CI](https://github.com/raj469-doit/SecurityAutomationToolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/raj469-doit/SecurityAutomationToolkit/actions/workflows/ci.yml)

A production-grade, Python-based security assessment framework designed to automate deterministic, OWASP-aligned website security validation. Built on the core principle of the **Triad of Integrity**—unifying rigorous Troubleshooting, Automated Quality Assurance, and Cybersecurity best practices.

## Architecture & Production Design
The toolkit is built using standard, isolated execution patterns that decouple live application scanning from localized test suites:
* **`security_score.py`**: The dynamic command-line core application. Enforces production-grade network defenses, sanitizes inputs to resolve domain-scoped historical baselines, and executes scans against any authorized target supplied via `--url`.
* **`tests/`**: Fully decoupled from live network traffic utilizing unit-level mocks. Allows validation logic (how scoring elements are weighted, parsed, and calculated) to run instantly inside automated environments (such as GitHub Actions) without firing live outbound HTTP requests, preventing external firewall blocks or API rate limits.

## Features

- **A01:2021-Broken Access Control Detection**
  - Sensitive File Exposure Probing (`.env`, `.git/config`, `application.properties`, database backups, and 10+ critical paths)
  - Admin Panel & API Surface Discovery (`/admin`, `/phpmyadmin`, `/swagger`, `/graphql`, and 6+ common endpoints)
  - Directory Listing Detection via signature matching across Apache, Nginx, and IIS response patterns
  - Graduated severity scoring distinguishing direct access (Critical/High) from redirect-inferred existence (Medium/Low)
- **A05:2021-Security Misconfiguration Auditing**
  - Robust Security Header Validation (HSTS, CSP, X-Frame-Options, etc.)
  - Automated Cookie Flag Verification (`Secure`, `HttpOnly` via standard cookiejar API boundaries)
- **Domain-Scoped Differential Analytics**
  - State tracking automatically sanitizes and isolates scanning baselines strictly by target hostname, preventing cross-tenant metric bleed.
  - Built-in delta logic evaluates consecutive runs for a specific domain, instantly flagging newly introduced vs. remediated exposures.
- **Dual-Asset Enterprise Reporting**
  - Compiles standalone, zero-dependency HTML5 visualization dashboards featuring pure CSS-only distribution graphics.
  - Automatically exports punchy, high-level Markdown executive briefings tailored for technical stakeholders and ticketing systems.
- **Application Target Discovery**
  - Native form parsing and target vector tracking powered by `BeautifulSoup`.
- **Continuous Integration / Continuous Deployment**
  - Strict linting validation powered by `Flake8`.
  - Ephemeral, deterministic testing layers executing under isolated network constraints.

## Technologies

- **Core Engine:** Python 3.12, Requests, BeautifulSoup4
- **Validation Framework:** PyTest (utilizing strict `unittest.mock` network isolation)
- **CI/CD Pipelines:** GitHub Actions Core Runner (with integrated Pip caching and Artifact preservation)
- **Static Analysis:** Flake8 Linting Execution Engine

## Project Architecture

```text
SecurityAutomationToolkit/
├── .github/workflows/
│   ├── test-suite.yml           # Continuous Integration (Runs unit tests & Flake8 syntax checks)
│   └── security-scan.yml        # On-Demand Scan Pipeline (Accepts targets via manual dispatch)
│
├── outputs/                     # Unified Output Workspace (Excluded from VC)
│   ├── latest_scan_example_com.json  # Domain-isolated historical baseline anchor
│   ├── security_dashboard.html       # Interactive CSS-only visualization dashboard
│   └── executive_brief.md            # Stakeholder Markdown briefing report
│
├── tests/                       # 100% Mocked Integration Checkpoints (37 tests)
│   ├── test_access_control.py   # A01:2021 Broken Access Control validation
│   ├── test_cookies.py
│   ├── test_forms.py
│   ├── test_headers.py
│   ├── test_robots.py
│   ├── test_scoring.py
│   ├── test_server_disclosure.py
│   ├── test_ssl.py
│   └── test_reporting.py        # Validates differential math and asset generation
│
├── security_score.py            # Primary CLI Scanner Engine & Reporting Orchestration
├── generate_report.py           # Metrics Aggregator and Reporting Compiler Core
├── requirements.txt             # Production Runtime Dependencies
└── requirements-dev.txt         # Quality Assurance & Engineering Tooling
```

## Setup & Installation

This toolkit leverages decoupled dependency mapping to preserve a minimal attack surface and ensure deployment efficiency. 

### Local Developer Installation (Full Suite + Testing tools)
To install the scanner along with the `pytest` and `flake8` engineering toolsets, execute the following within your virtual environment:

```bash
git clone [https://github.com/raj469-doit/SecurityAutomationToolkit.git](https://github.com/raj469-doit/SecurityAutomationToolkit.git)
cd SecurityAutomationToolkit
python -m venv venv
source venv/bin/activate  # On Windows use: .\venv\Scripts\activate

# Installs the development environment dependencies cleanly
pip install -r requirements-dev.txt
```

### Clean Production Installation (Scanner Only)
For headless deployment environments or continuous orchestration runners where test utilities are restricted:

```bash
pip install -r requirements.txt
```

## Usage Instructions

The toolkit functions as an automated CLI tool. Run the primary execution script while supplying a target URL parameter and a designated reporting output path:

```bash
python security_score.py --url "[https://sandbox.yourdomain.internal](https://sandbox.yourdomain.internal)" --output reports/production_run.html
```

### Validating the Framework Locally
To execute the local unit and integration tests under complete network isolation (without dispatching outbound traffic to live destination properties):

```bash
python -m pytest tests/ -v
```

## Automated Pipelines (GitHub Actions Description)
The repository incorporates two distinct, automated continuous operation profiles managed via GitHub Actions workflows:

### 1. The Test Suite Validator (test-suite.yml)
* **Trigger:** Automatically intercepts direct code push actions or pull_request interactions targeting the main branch. It also executes on a weekly cron schedule (0 2 * * 1) to monitor for third-party dependency drift.
* **Execution:** It spins up an ephemeral ubuntu-latest runner, provisions a Python 3.11 environment utilizing cached pip assets, checks layout syntax rules using flake8, and executes all unit tests under pytest.
* **Output:** Automatically compiles and preserves test metadata artifacts (junit/test-results.xml) even if specific validation checkpoints fail, allowing auditors to inspect full build execution history.

### 2. The Infrastructure Scanner (security-scan.yml)
* **Trigger:** An operational, on-demand pipeline manually triggered through GitHub's workflow_dispatch interface or via authenticated external API calls.
* **Execution:** Allows security operators to safely specify a live URL target parameter through the GitHub UI, setting up a completely clean runtime environment to scan infrastructure targets without dirtying local developer workspaces.
* **Output:** Produces clean security metric breakdowns and publishes HTML/Markdown validation logs directly back to the action runner storage space for security team review.

## Future Roadmap & Capability Maturity Model
The Security Automation Toolkit is actively developed under a phased release cycle. Development focuses on expanding the framework's assessment depth, refining data analytics/reporting capabilities, and hardening pipeline security.

### Phase 1: Core Foundation & Testing Isolation (100% Complete)
- [x] OWASP Misconfiguration Audits: Implemented deterministic checks for critical response headers, cross-site scripting guards, and client cookie attributes (Secure, HttpOnly).
- [x] Transport Layer Defenses: Stabilized connection exception tracking to gracefully evaluate missing, self-signed, or expired SSL/TLS certificates.
- [x] 100% Mocked Testing Architecture: Decoupled scanning mechanics from verification logic, leveraging unittest.mock to ensure zero out-of-band network traffic during local QA runs.
- [x] Initial CI/CD Gates: Configured automated GitHub Actions workflows with dual-trigger controls (push/workflow_dispatch), pip dependency caching, and rigid Flake8 syntax validation.

### Phase 2: OWASP Top 10 Alignment & Security Scoring (100% Complete)
- [x] Targeted Vulnerability Mapping: Map programmatic validation logic directly to OWASP A05:2021-Security Misconfiguration parameters to assess server configuration exposures.
- [x] Production-Grade Network Defenses: Swapped fragile assumption patterns inside security_score.py for strict request timeouts and graceful error handling, ensuring the app never hangs indefinitely on sluggish or offline targets.
- [x] Strict Posture Clamping Matrix: Engineer a deterministic mathematical scoring calculation engine that systematically docks weights based on findings, bound strictly by mathematical limits (0-100).
- [x] Complete Test Layer Decoupling: Refactor all validation check structures inside tests/ using unit-level mocks so local execution behaves identically to pipeline runners without live outward traffic dependencies.

### Phase 3: Enterprise Reporting & Executive Dashboards (100% Complete)
- [x] Dynamic HTML5/CSS Visualizations: Standalone interactive dashboards with color-coded severity charts (Critical, High, Medium, Low), letter grade display (A–F), OWASP category breakdown table, and severity metrics grid.
- [x] Executive Summary Generator: Markdown summaries with prioritized remediation checklists, severity icons, tabular metrics, and score trending vs previous scans.
- [x] Differential Scan Aggregation: Historical comparison engine that flags fixed and newly introduced exposures with itemized delta lists and score change tracking.
- [x] Remediation Checklist: Priority-ordered interactive checklist with checkboxes in HTML dashboard and numbered severity-ranked action items in Markdown output.

### Phase 4: OWASP A01:2021 Broken Access Control (100% Complete)
- [x] Sensitive File Exposure Detection: Probes 13 high-risk paths including `.env`, `.git/config`, `application.properties`, database backups, and framework configuration files.
- [x] Admin Panel & API Surface Discovery: Scans 9 common admin and API documentation endpoints with redirect-aware detection logic.
- [x] Directory Listing Detection: Identifies enabled directory listings using signature matching against known server response patterns.
- [x] Graduated Severity Scoring: Implements access-type-aware point deductions — directly accessible sensitive files cost 25 points while redirect-inferred admin paths cost 5, reflecting real-world risk differentiation.
- [x] Full Test Coverage: 10 new unit tests covering detection accuracy, severity classification, timeout resilience, and scoring integration. Suite total: 37/37 green.

### Phase 5: DevSecOps Hardening & Orchestration (In Progress)
- [ ] Strict Secret Vaulting Integration: Standardize target parsing inputs to smoothly ingest access tokens, authentication forms, and target URLs exclusively via secure environment managers (like GitHub Secrets or AWS Secrets Manager).
- [ ] Containerized Security Runners: Package the entire application suite into a minimal, hardened Docker image to eliminate host-level runner environment drifting and minimize the toolkit's attack surface.
- [ ] Concurrent Targeted Orchestration: Refactor the core engine's request loops to support async/multithreaded parsing, allowing operators to safely run parallel audits across multiple internal network environments simultaneously.
- [ ] A02:2021-Cryptographic Failures: Expand TLS validation beyond basic HTTPS detection to include cipher suite analysis, certificate chain verification, and protocol version auditing.
## Related Projects

This toolkit is part of a broader security portfolio. See also:

- **[LLM Security Lab](https://github.com/raj469-doit/llm-security-lab)** — 83 active test cases covering 5 OWASP LLM Top 10 categories: prompt injection, sensitive information disclosure, improper output handling, excessive agency, and system prompt leakage. Built with the same Python automation stack (Pytest, GitHub Actions).

## Disclaimer
This tool is intended for authorized security assessments and quality assurance validation tracking only. Scanning targets without explicit, written boundary permissions from the infrastructure owners is strictly prohibited.
