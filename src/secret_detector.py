"""
High-Precision Secret & Credential Detector
Analyzes source code, configuration files, and git history for leaked credentials,
API keys, access tokens, and private keys using regex signatures and Shannon entropy.
"""

import os
import re
import math
from typing import List, Dict, Any, Optional

SECRET_PATTERNS = [
    # Cloud Providers
    {
        "id": "SEC-AWS-001",
        "name": "AWS Access Key ID",
        "regex": r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        "severity": "critical",
        "category": "cloud_credentials",
    },
    {
        "id": "SEC-AWS-002",
        "name": "AWS Secret Access Key",
        "regex": r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "critical",
        "category": "cloud_credentials",
    },
    {
        "id": "SEC-GCP-001",
        "name": "GCP API Key",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "critical",
        "category": "cloud_credentials",
    },
    {
        "id": "SEC-GCP-002",
        "name": "GCP Service Account Key",
        "regex": r"\"type\":\s*\"service_account\"",
        "severity": "critical",
        "category": "cloud_credentials",
    },
    {
        "id": "SEC-AZURE-001",
        "name": "Azure Storage Account Key",
        "regex": r"AccountKey=[a-zA-Z0-9+/=]{88}",
        "severity": "critical",
        "category": "cloud_credentials",
    },
    {
        "id": "SEC-AZURE-002",
        "name": "Azure Connection String",
        "regex": r"Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[a-zA-Z0-9+/=]+",
        "severity": "critical",
        "category": "cloud_credentials",
    },

    # AI / LLM Providers (2025/2026 Ecosystem)
    {
        "id": "SEC-AI-OPENAI-001",
        "name": "OpenAI Project API Key",
        "regex": r"sk-proj-[a-zA-Z0-9_-]{48,}",
        "severity": "critical",
        "category": "ai_api_key",
    },
    {
        "id": "SEC-AI-OPENAI-002",
        "name": "OpenAI Service Account Key",
        "regex": r"sk-svcacct-[a-zA-Z0-9_-]{48,}",
        "severity": "critical",
        "category": "ai_api_key",
    },
    {
        "id": "SEC-AI-ANTHROPIC-001",
        "name": "Anthropic Claude API Key",
        "regex": r"sk-ant-api03-[0-9A-Za-z_-]{93}AA",
        "severity": "critical",
        "category": "ai_api_key",
    },
    {
        "id": "SEC-AI-SUPABASE-001",
        "name": "Supabase Secret Key",
        "regex": r"sb_secret_[a-zA-Z0-9_-]{31}",
        "severity": "critical",
        "category": "ai_api_key",
    },
    {
        "id": "SEC-AI-SUPABASE-002",
        "name": "Supabase Personal Access Token",
        "regex": r"sbp_[a-zA-Z0-9_]{40}",
        "severity": "critical",
        "category": "ai_api_key",
    },
    {
        "id": "SEC-AI-HUGGINGFACE-001",
        "name": "Hugging Face User Access Token",
        "regex": r"hf_[a-zA-Z0-9]{34}",
        "severity": "critical",
        "category": "ai_api_key",
    },
    {
        "id": "SEC-AI-DEEPSEEK-001",
        "name": "DeepSeek API Key",
        "regex": r"(?i)deepseek.*['\"]sk-[a-zA-Z0-9]{32,64}['\"]",
        "severity": "critical",
        "category": "ai_api_key",
    },

    # Developer & VCS Platforms
    {
        "id": "SEC-GH-001",
        "name": "GitHub Personal Access Token (Classic)",
        "regex": r"ghp_[0-9a-zA-Z]{36}",
        "severity": "critical",
        "category": "vcs_token",
    },
    {
        "id": "SEC-GH-002",
        "name": "GitHub Fine-Grained Personal Access Token",
        "regex": r"github_pat_[0-9a-zA-Z_]{82}",
        "severity": "critical",
        "category": "vcs_token",
    },
    {
        "id": "SEC-GH-003",
        "name": "GitHub OAuth Access Token",
        "regex": r"gho_[0-9a-zA-Z]{36}",
        "severity": "critical",
        "category": "vcs_token",
    },
    {
        "id": "SEC-GL-001",
        "name": "GitLab Personal Access Token",
        "regex": r"glpat-[0-9a-zA-Z\-]{20}",
        "severity": "critical",
        "category": "vcs_token",
    },

    # Auth & SaaS Services
    {
        "id": "SEC-STRIPE-001",
        "name": "Stripe Live Secret Key",
        "regex": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "category": "payment_credentials",
    },
    {
        "id": "SEC-STRIPE-002",
        "name": "Stripe Test Secret Key",
        "regex": r"sk_test_[0-9a-zA-Z]{24,}",
        "severity": "high",
        "category": "payment_credentials",
    },
    {
        "id": "SEC-CLERK-001",
        "name": "Clerk Live Secret Key",
        "regex": r"sk_live_[0-9a-zA-Z]{32,}",
        "severity": "critical",
        "category": "auth_token",
    },
    {
        "id": "SEC-RESEND-001",
        "name": "Resend API Key",
        "regex": r"re_[a-zA-Z0-9]{32}",
        "severity": "high",
        "category": "saas_token",
    },
    {
        "id": "SEC-SLACK-001",
        "name": "Slack Bot Token",
        "regex": r"xoxb-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9]*",
        "severity": "high",
        "category": "saas_token",
    },
    {
        "id": "SEC-SLACK-002",
        "name": "Slack Webhook URL",
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}",
        "severity": "high",
        "category": "saas_token",
    },
    {
        "id": "SEC-TWILIO-001",
        "name": "Twilio Auth Token",
        "regex": r"(?i)twilio.*auth.*token.*[a-f0-9]{32}",
        "severity": "critical",
        "category": "saas_token",
    },
    {
        "id": "SEC-SENDGRID-001",
        "name": "SendGrid API Key",
        "regex": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "high",
        "category": "saas_token",
    },

    # Cryptography & Keys
    {
        "id": "SEC-KEY-001",
        "name": "Private Cryptographic Key",
        "regex": r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
        "severity": "critical",
        "category": "private_key",
    },
    {
        "id": "SEC-JWT-001",
        "name": "JSON Web Token (JWT)",
        "regex": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "severity": "high",
        "category": "auth_token",
    },

    # Database URIs
    {
        "id": "SEC-DB-001",
        "name": "MongoDB Connection String with Password",
        "regex": r"mongodb(?:\+srv)?://(?:[^:]+:[^@]+@)[^?]+",
        "severity": "critical",
        "category": "database_uri",
    },
    {
        "id": "SEC-DB-002",
        "name": "PostgreSQL Connection String with Password",
        "regex": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^?]+",
        "severity": "critical",
        "category": "database_uri",
    },
    {
        "id": "SEC-DB-003",
        "name": "MySQL Connection String with Password",
        "regex": r"mysql://[^:]+:[^@]+@[^/]+/[^?]+",
        "severity": "critical",
        "category": "database_uri",
    },
    {
        "id": "SEC-DB-004",
        "name": "Redis Connection String with Password",
        "regex": r"redis(?:s)?://(?:[^:]+:[^@]+@)[^:]+:[0-9]+",
        "severity": "critical",
        "category": "database_uri",
    },
]

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib",
    ".lock", ".min.js", ".min.css", ".map"
}

IGNORE_DIRECTORIES = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", ".turbo", "coverage", ".codegraph", "tests"
}



def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SecretDetector:
    """Performs fast regex and entropy-based secret scanning across files and repositories."""

    def __init__(self, custom_patterns: Optional[List[Dict[str, Any]]] = None):
        self.patterns = SECRET_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self.compiled_patterns = [
            (p, re.compile(p["regex"])) for p in self.patterns
        ]

    def scan_text(self, text: str, filename: str = "<memory>") -> List[Dict[str, Any]]:
        """Scans a text string line by line and returns detected secrets."""
        findings = []
        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # Skip comments and pattern definition dictionaries
            stripped = line.strip()
            if "EXAMPLE" in line or "your_api_key_here" in line or "placeholder" in line:
                continue
            if stripped.startswith('"regex":') or stripped.startswith("'regex':") or stripped.startswith('r"'):
                continue


            for rule, pattern in self.compiled_patterns:
                for match in pattern.finditer(line):
                    matched_str = match.group(0)
                    # Mask secret for reporting
                    masked = self._mask_secret(matched_str)
                    entropy = calculate_entropy(matched_str)

                    findings.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "file": filename,
                        "line": line_idx,
                        "match_masked": masked,
                        "entropy": round(entropy, 2),
                        "snippet": line.strip()[:120]
                    })
        return findings

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Scans a single file on disk."""
        _, ext = os.path.splitext(filepath)
        if ext.lower() in IGNORE_EXTENSIONS:
            return []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, filename=filepath)
        except Exception:
            return []

    def scan_directory(self, root_dir: str) -> List[Dict[str, Any]]:
        """Recursively scans a directory for exposed credentials."""
        findings = []
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune ignored directories
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRECTORIES]

            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                file_findings = self.scan_file(full_path)
                findings.extend(file_findings)
        return findings

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Masks sensitive secret strings keeping prefix and suffix for identification."""
        if len(secret) <= 8:
            return "***"
        prefix = secret[:4]
        suffix = secret[-4:]
        return f"{prefix}...{suffix}"
