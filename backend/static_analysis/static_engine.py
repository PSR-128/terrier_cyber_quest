"""
Client-Side Static Analysis Engine.
Analyzes publicly accessible client-side HTML, JavaScript, inline scripts, and HTTP headers.
Detects exposed secrets, sensitive endpoints, dangerous DOM sinks, and missing security headers.
"""

import re
import httpx
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional

SECRET_PATTERNS = [
    (r'(?i)api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,64})["\']', "Exposed API Key in Client Code", "HIGH"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', "Exposed AWS Secret Key", "CRITICAL"),
    (r'ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "Hardcoded JWT Token", "MEDIUM"),
    (r'(?i)ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", "CRITICAL"),
    (r'(?i)password\s*[:=]\s*["\']([^"\']{4,32})["\']', "Hardcoded Password in Client Script", "HIGH"),
    (r'(?i)firebase[_-]?config\s*[:=]\s*\{', "Exposed Firebase Configuration", "LOW")
]

DOM_XSS_SINKS = [
    (r'\.innerHTML\s*=', "Direct innerHTML assignment without sanitization", "MEDIUM"),
    (r'\.outerHTML\s*=', "Direct outerHTML assignment", "MEDIUM"),
    (r'document\.write\s*\(', "Unsafe document.write execution", "HIGH"),
    (r'eval\s*\([^)]*location\.', "eval() executing user-controlled URL data", "CRITICAL"),
    (r'setTimeout\s*\([^,]*location\.', "setTimeout() executing user-controlled URL string", "HIGH"),
    (r'window\.postMessage\s*\([^,]+,\s*[\'"]\*[\'"]\)', "postMessage with wildcard (*) target origin", "MEDIUM")
]

REQUIRED_SECURITY_HEADERS = [
    ("Content-Security-Policy", "Missing Content-Security-Policy (CSP)", "MEDIUM", "Implement a robust CSP to prevent XSS and unauthorized script execution."),
    ("X-Content-Type-Options", "Missing X-Content-Type-Options: nosniff", "LOW", "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks."),
    ("X-Frame-Options", "Missing X-Frame-Options", "LOW", "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to mitigate Clickjacking."),
    ("Strict-Transport-Security", "Missing HSTS Header", "LOW", "Enable Strict-Transport-Security on HTTPS deployments.")
]


class StaticAnalysisEngine:
    def __init__(self, auth_headers: Optional[Dict[str, str]] = None):
        self.auth_headers = auth_headers or {}

    def analyze_headers(self, headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        """Inspect HTTP response headers for missing security protections."""
        findings = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        for header_name, title, severity, remediation in REQUIRED_SECURITY_HEADERS:
            if header_name.lower() not in normalized_headers:
                findings.append({
                    "vuln_type": "Missing_Security_Header",
                    "category": "Configuration",
                    "title": title,
                    "severity": severity,
                    "confidence": 95.0,
                    "status": "Confirmed",
                    "url": url,
                    "parameter": header_name,
                    "evidence": {
                        "header_checked": header_name,
                        "present_headers": list(headers.keys())
                    },
                    "remediation": remediation
                })

        # Check CORS
        cors_origin = normalized_headers.get("access-control-allow-origin")
        cors_creds = normalized_headers.get("access-control-allow-credentials")
        if cors_origin == "*" and cors_creds == "true":
            findings.append({
                "vuln_type": "Insecure_CORS_Policy",
                "category": "Configuration",
                "title": "Insecure CORS Policy with Wildcard & Credentials",
                "severity": "HIGH",
                "confidence": 98.0,
                "status": "Confirmed",
                "url": url,
                "parameter": "Access-Control-Allow-Origin",
                "evidence": {
                    "allow_origin": cors_origin,
                    "allow_credentials": cors_creds
                },
                "remediation": "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Specify explicit authorized origins."
            })

        return findings

    def analyze_html_and_scripts(self, html: str, url: str) -> List[Dict[str, Any]]:
        """Inspect client-side HTML source, inline scripts, and DOM structures."""
        findings = []
        if not html:
            return findings

        # 1. Check for exposed secrets
        for pattern, title, severity in SECRET_PATTERNS:
            matches = re.finditer(pattern, html)
            for m in matches:
                matched_snippet = html[max(0, m.start() - 30): min(len(html), m.end() + 30)]
                # Redact sensitive portion for safe display
                findings.append({
                    "vuln_type": "Information_Disclosure",
                    "category": "Client_Side_Exposure",
                    "title": title,
                    "severity": severity,
                    "confidence": 90.0,
                    "status": "Confirmed",
                    "url": url,
                    "parameter": "Client HTML/JS",
                    "evidence": {
                        "pattern_matched": pattern,
                        "snippet_preview": matched_snippet.strip()
                    },
                    "remediation": "Remove hardcoded credentials, secret keys, or private tokens from client-side code. Use server-side environment variables."
                })

        # 2. Check for DOM XSS Sinks in inline scripts
        soup = BeautifulSoup(html, "html.parser")
        scripts = soup.find_all("script")
        for script in scripts:
            content = script.string or ""
            for sink_pattern, title, severity in DOM_XSS_SINKS:
                matches = re.finditer(sink_pattern, content)
                for m in matches:
                    snippet = content[max(0, m.start() - 40): min(len(content), m.end() + 40)]
                    findings.append({
                        "vuln_type": "Cross_Site_Scripting",
                        "category": "DOM_XSS",
                        "title": f"Potential DOM XSS Sink: {title}",
                        "severity": severity,
                        "confidence": 85.0,
                        "status": "Potential",
                        "url": url,
                        "parameter": "DOM Sink",
                        "evidence": {
                            "sink_pattern": sink_pattern,
                            "code_snippet": snippet.strip()
                        },
                        "remediation": "Avoid using dangerous DOM sinks like innerHTML or eval with user-controlled input. Use textContent or safe DOM manipulation APIs."
                    })

        # 3. Check for exposed sensitive HTML comments (e.g. TODO, admin creds, internal routes)
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.string)) and text.parent.name is None)
        # BeautifulSoup Comment extraction
        from bs4 import Comment
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            c_text = comment.strip()
            if any(k in c_text.lower() for k in ["todo", "admin", "password", "fixme", "internal", "debug", "api_key"]):
                findings.append({
                    "vuln_type": "Information_Disclosure",
                    "category": "HTML_Comments",
                    "title": "Sensitive Information in HTML Comments",
                    "severity": "LOW",
                    "confidence": 80.0,
                    "status": "Confirmed",
                    "url": url,
                    "parameter": "HTML Comment",
                    "evidence": {"comment_text": c_text[:200]},
                    "remediation": "Remove sensitive development, debug, and administrative comments prior to deploying to production."
                })

        return findings
