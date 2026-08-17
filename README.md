# 🛡️ Security Research Program & Sentinel Suite

An enterprise-grade, autonomous security research engine and multi-layer static analysis gate designed for modern AI, Next.js, Node.js, and Python application architectures.

---

## 🚀 Key Capabilities

1. **Multi-Layer Static Analysis**:
   - **Layer 1: Secrets Detection** — Integrated Gitleaks & native entropy-based secret scanning for 35+ provider token patterns (OpenAI, Anthropic, Gemini, Groq, DeepSeek, Supabase, Hugging Face, Resend, Clerk, GitHub PATs, AWS, GCP, Azure).
   - **Layer 2: SAST (Static Application Security Testing)** — Semgrep and Bandit integration targeting OWASP Top 10 and GenAI LLM vulnerabilities.
   - **Layer 3: Dependency Vulnerabilities** — Continuous scanning via `pip-audit`, `osv-scanner`, `trivy`, and `npm audit`.
   - **Layer 4: Infrastructure & Configuration** — Docker, Kubernetes, and cloud IaC security checks.
   - **Layer 5: Agent-Native Heuristics** — Specialized AST/regex rules for React Server Components (RSC) Flight protocol validation, Server Actions authorization, and LLM prompt injection safeguards.
   - **Layer 6: Supply Chain & Typosquatting** — Detection of compromised upstream dependencies.

2. **Automated Threat Intelligence Research**:
   - Real-time querying against OSV.dev, GitHub Security Advisory Database, and NVD.
   - Automated generation of Markdown research briefings and structured CVE catalogs.
   - Built-in tracking of critical 2025/2026 threats (React2Shell CVE-2025-55182, Next.js CVE-2026-64641, Django ORM CVE-2025-64459).

---

## 🛠️ Toolchain Status

| Tool | Capability | Status |
| :--- | :--- | :--- |
| `semgrep` | Multi-language SAST & Custom Pattern Matching | ✅ Active |
| `gitleaks` | Fast Git & Worktree Credential Scanning | ✅ Active |
| `trivy` | Container, IaC, and Dependency Scanning | ✅ Active |
| `bandit` | Python AST Security Scanner | ✅ Active |
| `pip-audit` | Python Package Vulnerability Auditing | ✅ Active |
| `osv-scanner` | Open Source Vulnerability Registry Scanner | ✅ Active |
| `npm audit` | Node.js Dependency Security Scanner | ✅ Active |

---

## 💻 CLI Usage

```powershell
# Check environment toolchain status
python -m src.cli status

# Run automated threat intelligence research sweep
python -m src.cli research

# Scan current project or target directory for leaked secrets
python -m src.cli secrets --target .

# Run full multi-layer security gate audit
python -m src.cli scan --target .
```

---

## 📂 Project Structure

```
security/
├── .security-sentinel.yaml       # Sentinel security gate configuration
├── requirements.txt              # Python dependencies
├── README.md                     # Documentation
├── src/
│   ├── __init__.py
│   ├── cli.py                   # Unified CLI entrypoint
│   ├── secret_detector.py       # Regex + Shannon entropy secret scanner
│   ├── research_engine.py       # OSV.dev / CVE research aggregator
│   └── scanner_suite.py         # Multi-layer tool orchestrator
├── research/
│   ├── 2026_threat_landscape.md # Deep research briefing on 2026 threats
│   └── cve_intel_database.json  # Structured CVE catalog
└── tests/
    ├── test_secret_detector.py  # Secret detector test suite
    └── test_research_engine.py  # Research engine test suite
```

---

## 🧪 Testing

Run test suite via Python standard unittest:

```powershell
python -m unittest discover tests
```
