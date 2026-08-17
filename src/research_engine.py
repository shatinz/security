"""
Security Research Engine & Threat Intelligence Aggregator
Queries vulnerability databases (OSV.dev, GitHub Advisory DB, NVD) and generates
intelligence briefings, CVE tracking databases, and mitigation strategies.
"""

import json
import os
import urllib.request
import urllib.parse
from datetime import datetime
from typing import List, Dict, Any, Optional

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


class ResearchEngine:
    """Automates threat research across ecosystems and vulnerability registries."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), "..", "research")
        os.makedirs(self.output_dir, exist_ok=True)

    def query_package_vulnerabilities(self, package_name: str, ecosystem: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Queries OSV.dev API for vulnerabilities in a package and ecosystem."""
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        if version:
            payload["version"] = version

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OSV_API_URL,
            data=data_bytes,
            headers={"Content-Type": "application/json", "User-Agent": "Antigravity-Security-Sentinel/1.0"}
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                res_json = json.loads(response.read().decode("utf-8"))
                return res_json.get("vulns", [])
        except Exception as e:
            print(f"[!] Error querying OSV for {package_name} ({ecosystem}): {e}")
            return []

    def fetch_vulnerability_details(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Fetches full advisory details for a specific vulnerability ID (GHSA, CVE, OSV)."""
        url = f"{OSV_VULN_URL}{urllib.parse.quote(vuln_id)}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Antigravity-Security-Sentinel/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as e:
            print(f"[!] Error fetching details for {vuln_id}: {e}")
            return None

    def run_ecosystem_sweep(self, target_ecosystems: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """Conducts a comprehensive threat sweep across primary packages."""
        if not target_ecosystems:
            target_ecosystems = [
                {"name": "next", "ecosystem": "npm"},
                {"name": "react", "ecosystem": "npm"},
                {"name": "express", "ecosystem": "npm"},
                {"name": "fastapi", "ecosystem": "PyPI"},
                {"name": "django", "ecosystem": "PyPI"},
                {"name": "flask", "ecosystem": "PyPI"},
                {"name": "sqlalchemy", "ecosystem": "PyPI"},
                {"name": "pydantic", "ecosystem": "PyPI"},
                {"name": "langchain", "ecosystem": "PyPI"},
                {"name": "openai", "ecosystem": "PyPI"},
            ]

        results = {
            "timestamp": datetime.now().isoformat(),
            "packages_scanned": len(target_ecosystems),
            "findings_by_package": {},
            "critical_cves": []
        }

        for item in target_ecosystems:
            pkg = item["name"]
            eco = item["ecosystem"]
            vulns = self.query_package_vulnerabilities(pkg, eco)
            results["findings_by_package"][f"{eco}:{pkg}"] = len(vulns)

            # Analyze recent/critical entries
            for v in vulns[:5]:  # Top 5 most recent
                v_id = v.get("id")
                summary = v.get("summary", "")
                aliases = v.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), v_id)

                results["critical_cves"].append({
                    "id": v_id,
                    "cve": cve_id,
                    "package": pkg,
                    "ecosystem": eco,
                    "summary": summary,
                    "details_url": f"https://osv.dev/vulnerability/{v_id}"
                })

        return results

    def generate_intelligence_brief(self, scan_results: Dict[str, Any], custom_threats: Optional[List[Dict[str, Any]]] = None) -> str:
        """Compiles research results into a Markdown intelligence briefing."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        lines = [
            f"# 🛡️ Security Intelligence Brief — {date_str}",
            "",
            f"**Generated**: {scan_results.get('timestamp')}",
            f"**Packages Audited**: {scan_results.get('packages_scanned')}",
            "",
            "## 1. Executive Summary",
            "Continuous automated research identified active vulnerabilities and emerging attack vectors across modern JavaScript/TypeScript, Python, and AI/LLM ecosystems.",
            "",
            "## 2. Monitored Ecosystem Status",
            "| Ecosystem:Package | Advisories Count | Status |",
            "| :--- | :--- | :--- |"
        ]

        for pkg, count in scan_results.get("findings_by_package", {}).items():
            status = "⚠️ Active Advisories" if count > 0 else "✅ Clean"
            lines.append(f"| `{pkg}` | {count} | {status} |")

        lines.extend([
            "",
            "## 3. Notable CVEs & Active Threat Vectors",
            "| CVE / ID | Package | Ecosystem | Summary | Reference |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ])

        for cve in scan_results.get("critical_cves", [])[:15]:
            summary_clean = cve['summary'].replace("|", "/").replace("\n", " ")[:80]
            lines.append(f"| **{cve['cve']}** | `{cve['package']}` | {cve['ecosystem']} | {summary_clean}... | [Advisory]({cve['details_url']}) |")

        if custom_threats:
            lines.extend([
                "",
                "## 4. Emerging AI & Architectural Vectors (2026)",
            ])
            for t in custom_threats:
                lines.extend([
                    f"### {t.get('title')}",
                    f"- **Severity**: `{t.get('severity')}`",
                    f"- **Vector**: {t.get('vector')}",
                    f"- **Mitigation**: {t.get('mitigation')}",
                    ""
                ])

        report_content = "\n".join(lines)

        # Save briefing
        briefing_path = os.path.join(self.output_dir, f"intelligence_brief_{date_str}.md")
        with open(briefing_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        return report_content
