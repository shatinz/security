"""
Multi-Layer Scanner Suite Orchestrator
Executes integrated security tools (Semgrep, Gitleaks, Trivy, Bandit, pip-audit, osv-scanner)
and agent-native heuristics, aggregating findings into unified audit reports.
"""

import os
import json
import subprocess
import shutil
from datetime import datetime
from typing import List, Dict, Any, Optional
from .secret_detector import SecretDetector


class ScannerSuite:
    """Orchestrates security scanning tools and normalizes findings."""

    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)
        self.secret_detector = SecretDetector()
        self.tools_status = self._detect_tools()

    def _detect_tools(self) -> Dict[str, Dict[str, Any]]:
        """Detects available CLI tools on the system."""
        tools = ["semgrep", "gitleaks", "trivy", "bandit", "pip-audit", "osv-scanner", "npm"]
        status = {}
        for tool in tools:
            path = shutil.which(tool)
            status[tool] = {
                "available": path is not None,
                "path": path or ""
            }
        return status

    def scan_secrets(self) -> List[Dict[str, Any]]:
        """Runs Gitleaks if available, with SecretDetector fallback."""
        findings = []

        if self.tools_status["gitleaks"]["available"]:
            report_file = os.path.join(self.target_dir, ".temp_gitleaks.json")
            cmd = [
                "gitleaks", "detect",
                "--source", self.target_dir,
                "--report-format", "json",
                "--report-path", report_file,
                "--no-banner"
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, cwd=self.target_dir)
                if os.path.exists(report_file):
                    with open(report_file, "r", encoding="utf-8") as f:
                        g_data = json.load(f)
                    for item in g_data:
                        findings.append({
                            "id": "SEC-GITLEAKS",
                            "layer": "secret-detection",
                            "severity": "critical",
                            "title": item.get("Description", "Detected Secret"),
                            "file": item.get("File", ""),
                            "line": item.get("StartLine", 0),
                            "match": item.get("Match", ""),
                            "tool": "Gitleaks"
                        })
                    try:
                        os.remove(report_file)
                    except OSError:
                        pass
            except Exception as e:
                print(f"[!] Gitleaks scan error: {e}")

        # Always augment with native SecretDetector
        native_findings = self.secret_detector.scan_directory(self.target_dir)
        for nf in native_findings:
            findings.append({
                "id": nf["id"],
                "layer": "secret-detection",
                "severity": nf["severity"],
                "title": f"Hardcoded Secret: {nf['name']}",
                "file": nf["file"],
                "line": nf["line"],
                "match": nf["match_masked"],
                "tool": "SecretDetector-Native"
            })

        return findings

    def scan_sast_semgrep(self) -> List[Dict[str, Any]]:
        """Executes Semgrep static analysis."""
        findings = []
        if not self.tools_status["semgrep"]["available"]:
            return findings

        report_file = os.path.join(self.target_dir, ".temp_semgrep.json")
        cmd = [
            "semgrep", "scan",
            "--config", "auto",
            "--json",
            "--output", report_file,
            "--metrics", "off"
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, cwd=self.target_dir)
            if os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for res in data.get("results", []):
                    sev = res.get("extra", {}).get("severity", "WARNING").lower()
                    mapped_sev = "critical" if sev == "error" else ("high" if sev == "warning" else "medium")
                    findings.append({
                        "id": res.get("check_id", "SEMGREP-RULE"),
                        "layer": "sast",
                        "severity": mapped_sev,
                        "title": res.get("extra", {}).get("message", "Static Analysis Finding"),
                        "file": res.get("path", ""),
                        "line": res.get("start", {}).get("line", 0),
                        "cwe": res.get("extra", {}).get("metadata", {}).get("cwe", []),
                        "tool": "Semgrep"
                    })
                try:
                    os.remove(report_file)
                except OSError:
                    pass
        except Exception as e:
            print(f"[!] Semgrep scan error: {e}")

        return findings

    def scan_sast_bandit(self) -> List[Dict[str, Any]]:
        """Executes Bandit AST security analysis for Python code."""
        findings = []
        if not self.tools_status.get("bandit", {}).get("available"):
            return findings

        tests_path = os.path.join(self.target_dir, "tests")
        cmd = [
            "bandit", "-r", self.target_dir,
            "-f", "json",
            "-q",
            "-x", tests_path
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=self.target_dir)
            if proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    for res in data.get("results", []):
                        sev_raw = res.get("issue_severity", "LOW").lower()
                        mapped_sev = "critical" if sev_raw == "high" else ("high" if sev_raw == "medium" else "low")
                        cwe_link = res.get("issue_cwe", {}).get("link", "")
                        cwe_list = [cwe_link] if cwe_link else []
                        findings.append({
                            "id": res.get("test_id", "BANDIT-RULE"),
                            "layer": "sast",
                            "severity": mapped_sev,
                            "title": res.get("issue_text", "Python AST Security Finding"),
                            "file": res.get("filename", ""),
                            "line": res.get("line_number", 0),
                            "cwe": cwe_list,
                            "tool": "Bandit"
                        })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"[!] Bandit scan error: {e}")

        return findings

    def scan_dependencies(self) -> List[Dict[str, Any]]:
        """Audits project dependencies using pip-audit or npm."""
        findings = []
        req_file = os.path.join(self.target_dir, "requirements.txt")
        if os.path.exists(req_file) and self.tools_status.get("pip-audit", {}).get("available"):
            cmd = ["pip-audit", "-r", req_file, "-f", "json"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, cwd=self.target_dir)
                if proc.stdout:
                    try:
                        data = json.loads(proc.stdout)
                        deps = data.get("dependencies", []) if isinstance(data, dict) else []
                        for dep in deps:
                            for vuln in dep.get("vulns", []):
                                findings.append({
                                    "id": vuln.get("id", "DEP-VULN"),
                                    "layer": "dependency",
                                    "severity": "high",
                                    "title": f"Vulnerable dependency: {dep.get('name')} ({vuln.get('id')})",
                                    "file": "requirements.txt",
                                    "line": 1,
                                    "cwe": vuln.get("aliases", []),
                                    "tool": "pip-audit"
                                })
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                print(f"[!] pip-audit scan error: {e}")

        pkg_json = os.path.join(self.target_dir, "package.json")
        if os.path.exists(pkg_json) and self.tools_status.get("npm", {}).get("available"):
            cmd = ["npm", "audit", "--json"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, cwd=self.target_dir)
                if proc.stdout:
                    try:
                        data = json.loads(proc.stdout)
                        vulnerabilities = data.get("vulnerabilities", {})
                        for pkg_name, info in vulnerabilities.items():
                            sev_raw = info.get("severity", "moderate").lower()
                            mapped_sev = "critical" if sev_raw == "critical" else ("high" if sev_raw == "high" else "medium")
                            findings.append({
                                "id": f"NPM-{pkg_name.upper()}",
                                "layer": "dependency",
                                "severity": mapped_sev,
                                "title": f"Vulnerable npm package: {pkg_name}",
                                "file": "package.json",
                                "line": 1,
                                "tool": "npm-audit"
                            })
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                print(f"[!] npm audit scan error: {e}")

        return findings

    def run_full_audit(self) -> Dict[str, Any]:
        """Runs all enabled scanning layers and aggregates results."""
        secrets = self.scan_secrets()
        sast_semgrep = self.scan_sast_semgrep()
        sast_bandit = self.scan_sast_bandit()
        deps = self.scan_dependencies()

        all_findings = secrets + sast_semgrep + sast_bandit + deps
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for f in all_findings:
            sev = f.get("severity", "medium").lower()
            severities[sev] = severities.get(sev, 0) + 1

        decision = "✅ PASSED"
        if severities["critical"] > 0 or severities["high"] > 0:
            decision = "🛑 BLOCKED" if severities["critical"] > 0 else "⚠️ WARNING"

        return {
            "timestamp": datetime.now().isoformat(),
            "target_dir": self.target_dir,
            "gate_decision": decision,
            "severity_counts": severities,
            "tools_status": self.tools_status,
            "findings": all_findings
        }
