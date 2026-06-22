# Security Automation Toolkit

[![Core Framework Test Suite](https://github.com/raj469-doit/SecurityAutomationToolkit/actions/workflows/test-suite.yml/badge.svg)](https://github.com/raj469-doit/SecurityAutomationToolkit/actions/workflows/test-suite.yml)
[![Live Security Infrastructure Scan](https://github.com/raj469-doit/SecurityAutomationToolkit/actions/workflows/security-scan.yml/badge.svg)](https://github.com/raj469-doit/SecurityAutomationToolkit/actions/workflows/security-scan.yml)

A production-grade, Python-based security assessment framework designed to automate deterministic, OWASP-aligned website security validation. Built on the core principle of the **Triad of Integrity**—unifying rigorous Troubleshooting, Automated Quality Assurance, and Cybersecurity best practices.

## Features

- **A05:2021-Security Misconfiguration Auditing**
  - Robust Security Header Validation (HSTS, CSP, X-Frame-Options, etc.)
  - Automated Cookie Flag Verification (`Secure`, `HttpOnly`, SameSite tracking)
- **Transport Layer Posture Checks**
  - Comprehensive SSL/TLS Validation (handles structural certificate anomalies, expiries, and connection faults cleanly)
- **Application Target Discovery**
  - Native `robots.txt` and Sitemap structural parsing via `BeautifulSoup`
  - Automated form parsing and target vector tracking
- **Continuous Integration / Continuous Deployment**
  - Strict linting validation powered by `Flake8`
  - Ephemeral, deterministic testing layers executing under isolated network constraints

## Technologies

- **Core Engine:** Python 3.11, Requests, BeautifulSoup4
- **Validation Framework:** PyTest (utilizing strict `unittest.mock` network isolation)
- **CI/CD Pipelines:** GitHub Actions Core Runner (with integrated Pip caching and Artifact preservation)
- **Static Analysis:** Flake8 Linting Execution Engine

## Project Architecture

```text
SecurityAutomationToolkit/
│
├── .github/workflows/
│   ├── test-suite.yml           # Continuous Integration (Runs unit tests & Flake8 syntax checks)
│   └── security-scan.yml        # On-Demand Scan Pipeline (Accepts targets via manual dispatch)
│
├── tests/                       # 100% Mocked Integration Checkpoints
│   ├── test_cookies.py
│   ├── test_forms.py
│   ├── test_ssl.py
│   └── test_security_score.py
│
├── security_score.py            # Primary CLI Scanner Execution Engine
├── generate_report.py           # Metrics Aggregator and Reporting Compiler
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

### Phase 1: Core Foundation & Testing Isolation (100% Completed)
- [x] OWASP Misconfiguration Audits: Implemented deterministic checks for critical response headers, cross-site scripting guards, and client cookie attributes (Secure, HttpOnly).
- [x] Transport Layer Defenses: Stabilized connection exception tracking to gracefully evaluate missing, self-signed, or expired SSL/TLS certificates.
- [x] 100% Mocked Testing Architecture: Decoupled scanning mechanics from verification logic, leveraging unittest.mock to ensure zero out-of-band network traffic during local QA runs.
- [x] Initial CI/CD Gates: Configured automated GitHub Actions workflows with dual-trigger controls (push/workflow_dispatch), pip dependency caching, and rigid Flake8 syntax validation.

### Phase 2: Vulnerability Depth & Telemetry Expansion (In Progress)
- [ ] Dynamic Attack Vector Mapping: Expand form parsing algorithms to detect and map parameters vulnerable to basic injection variants (e.g., Cross-Site Scripting stubs, SQLi patterns).
- [ ] Advanced Certificate Analytics: Migrate from simple connection validation to deep cryptographic parsing, extracting specific cipher suite configurations, expiration countdowns, and signature algorithms.
- [ ] Robust Local Data Storage: Transition from loose text logging to a structured workspace structure, safely writing telemetry data into an isolated local database layer (e.g., SQLite) prior to report formatting.

### Phase 3: Enterprise Reporting & Executive Dashboards (Planned)
- [ ] Dynamic HTML5/CSS Visualizations: Upgrade the HTML reporting engine to compile standalone, interactive dashboards complete with color-coded severity charts (Critical, High, Medium, Low).
- [ ] Executive Summary Generator: Introduce a compilation module that automatically exports clean, high-level Markdown summaries suitable for direct inclusion in vulnerability management systems or emails to non-technical stakeholders.
- [ ] Differential Scan Aggregation: Build a historical metrics comparison engine that checks the results of a new scan against a past report to highlight fixed or newly introduced exposures.

### Phase 4: DevSecOps Hardening & Orchestration (Long-Term Vision)
- [ ] Strict Secret Vaulting Integration: Standardize target parsing inputs to smoothly ingest access tokens, authentication forms, and target URLs exclusively via secure environment managers (like GitHub Secrets or AWS Secrets Manager).
- [ ] Containerized Security Runners: Package the entire application suite into a minimal, hardened Docker image to eliminate host-level runner environment drifting and minimize the toolkit's attack surface.
- [ ] Concurrent Targeted Orchestration: Refactor the core engine's request loops to support async/multithreaded parsing, allowing operators to safely run parallel audits across multiple internal network environments simultaneously.

## Disclaimer
This tool is intended for authorized security assessments and quality assurance validation tracking only. Scanning targets without explicit, written boundary permissions from the infrastructure owners is strictly prohibited.
