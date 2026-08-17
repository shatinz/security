"""
Unified Command Line Interface for Security Research Program
"""

import sys
import os
import json
import click

# Ensure utf-8 encoding on standard streams
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .secret_detector import SecretDetector
from .research_engine import ResearchEngine
from .scanner_suite import ScannerSuite


@click.group()
def cli():
    """Antigravity Security Research & Sentinel Suite."""
    pass


@cli.command()
@click.option("--output", "-o", default=None, help="Output directory for research reports")
def research(output):
    """Run automated threat intelligence research sweep across primary ecosystems."""
    click.secho("[*] Initializing Security Research Engine...", fg="cyan")
    engine = ResearchEngine(output_dir=output)
    
    click.secho("[*] Querying vulnerability databases (OSV.dev, GitHub Advisory DB)...", fg="cyan")
    sweep_results = engine.run_ecosystem_sweep()
    
    custom_threats = [
        {
            "title": "React Server Components (RSC) Flight Protocol RCE (React2Shell / CVE-2025-55182)",
            "severity": "CRITICAL (CVSS 10.0)",
            "vector": "Unauthenticated malicious HTTP payloads targeting RSC Flight deserializer",
            "mitigation": "Upgrade React >= 19.2.1 and Next.js >= 15.1.9 / 16.0.7"
        },
        {
            "title": "Next.js Server Actions CPU Exhaustion & DoS (CVE-2026-64641)",
            "severity": "HIGH (CVSS 7.5)",
            "vector": "Excessive compute triggering DoS via unbounded Server Action calls",
            "mitigation": "Implement rate limiting and session validation in all 'use server' functions"
        },
        {
            "title": "Django ORM Query Parameter Injection (CVE-2025-64459)",
            "severity": "CRITICAL (CVSS 9.1)",
            "vector": "Injecting _connector / _negated internal keys through unvalidated user inputs",
            "mitigation": "Upgrade to Django 5.2.8, 5.1.14, or 4.2.26; validate dictionary keys in query filters"
        },
        {
            "title": "OWASP GenAI LLM Top 10 2026 Release (LLM01-LLM10)",
            "severity": "HIGH",
            "vector": "Multimodal prompt injection, excessive agency tool misuse, hidden context leakage",
            "mitigation": "Apply blast radius isolation, DLP token scrubbing, sandbox tool execution"
        }
    ]
    
    brief = engine.generate_intelligence_brief(sweep_results, custom_threats=custom_threats)
    click.secho("[+] Threat intelligence research completed successfully!", fg="green")
    click.echo(brief[:1000] + "\n...\n[Full report saved to research/ directory]")


@cli.command()
@click.option("--target", "-t", default=".", help="Target directory to scan")
def scan(target):
    """Run multi-layer security scan on target directory."""
    click.secho(f"[*] Starting multi-layer security audit on: {target}", fg="cyan")
    suite = ScannerSuite(target_dir=target)
    results = suite.run_full_audit()

    decision = results["gate_decision"]
    color = "green" if "PASSED" in decision else ("red" if "BLOCKED" in decision else "yellow")
    
    click.secho(f"\n[!] SECURITY GATE DECISION: {decision}", fg=color, bold=True)
    click.echo(f"Critical: {results['severity_counts']['critical']} | High: {results['severity_counts']['high']} | Medium: {results['severity_counts']['medium']}")
    
    if results["findings"]:
        click.secho("\n--- Findings ---", fg="yellow")
        for f in results["findings"][:10]:
            click.echo(f"[{f.get('severity').upper()}] {f.get('title')} ({f.get('tool')}) -> {f.get('file')}:{f.get('line')}")
    else:
        click.secho("\n[+] No critical vulnerabilities or secrets detected.", fg="green")


@cli.command()
@click.option("--target", "-t", default=".", help="Target directory or file to scan for secrets")
def secrets(target):
    """Scan directory or file for exposed credentials and API keys."""
    click.secho(f"[*] Scanning for secrets in: {target}", fg="cyan")
    detector = SecretDetector()
    if os.path.isfile(target):
        findings = detector.scan_file(target)
    else:
        findings = detector.scan_directory(target)

    if findings:
        click.secho(f"[!] Found {len(findings)} exposed secrets!", fg="red", bold=True)
        for item in findings:
            click.echo(f"  - [{item['severity'].upper()}] {item['name']} in {item['file']}:{item['line']} (Entropy: {item['entropy']})")
    else:
        click.secho("[+] No exposed secrets detected.", fg="green")


@cli.command()
def status():
    """Display installed toolchain status and environment health."""
    suite = ScannerSuite()
    click.secho("[*] Security Toolchain Status:", fg="cyan")
    for tool, info in suite.tools_status.items():
        tag = "[INSTALLED]    " if info["available"] else "[NOT INSTALLED]"
        fg_col = "green" if info["available"] else "yellow"
        click.secho(f"  {tag} {tool:<12} : {info['path'] or 'N/A'}", fg=fg_col)


if __name__ == "__main__":
    cli()

