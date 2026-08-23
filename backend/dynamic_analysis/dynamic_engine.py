"""
Dynamic Response and Behavioral Analysis Engine.
Executes non-destructive security tests and analyzes HTTP response differentials,
error signatures, canary reflections, and template/command outputs.
"""

import time
import httpx
import re
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse, urlencode, parse_qsl
from backend.crawler.crawler import DiscoveredEndpoint
from backend.fuzzing.payload_generator import PROBES, CANARY_ID

# Known DBMS and framework error patterns
SQL_ERROR_SIGNATURES = [
    (r'(?i)you have an error in your sql syntax', 'MySQL'),
    (r'(?i)warning:\s*mysql_', 'MySQL'),
    (r'(?i)unclosed quotation mark after the character string', 'MSSQL'),
    (r'(?i)quoted string not properly terminated', 'Oracle'),
    (r'(?i)pg_query\(\):\s*Query failed:', 'PostgreSQL'),
    (r'(?i)sqlite3\.operationalerror', 'SQLite'),
    (r'(?i)near "[^"]+": syntax error', 'SQLite'),
    (r'(?i)syntax error at or near', 'PostgreSQL'),
    (r'(?i)microsoft ole db provider for odbc drivers', 'MSSQL'),
    (r'(?i)org\.hibernate\.hql\.internal\.ast\.QuerySyntaxException', 'Hibernate HQL')
]

TRAVERSAL_INDICATORS = [
    r'root:.*?:0:0:',
    r'\[boot loader\]',
    r'\[fonts\]',
    r'127\.0\.0\.1\s+localhost',
    r'daemon:.*?:1:1:'
]


class DynamicAnalysisEngine:
    def __init__(
        self,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        timeout: float = 8.0,
        stop_checker: Optional[Callable[[], bool]] = None,
        on_probe_executed: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.timeout = timeout
        self.stop_checker = stop_checker
        self.on_probe_executed = on_probe_executed

    async def execute_probe(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        payload_obj: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Send a single probe request and capture response metrics."""
        url = endpoint.url
        method = endpoint.method
        payload = payload_obj["payload"]

        req_headers = {
            "User-Agent": "TerrierCyberQuest-Scanner/2.0 (Security Differential Analyzer)",
            **self.auth_headers
        }

        # Build raw request representation for ML scoring
        raw_req_preview = f"{method} {url} HTTP/1.1\n"

        try:
            start_t = time.time()
            if method == "GET":
                # Inject into query params
                parsed = urlparse(url)
                params_dict = dict(parse_qsl(parsed.query))
                params_dict[param_name] = payload
                clean_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                raw_req_preview = f"GET {clean_base}?{urlencode(params_dict)} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\nAccept: */*"
                
                resp = await client.get(
                    clean_base,
                    params=params_dict,
                    headers=req_headers,
                    cookies=self.auth_cookies,
                    timeout=self.timeout
                )
            elif method == "POST":
                # Inject into form or json body
                body_dict = {p["name"]: p.get("sample_value", "") for p in endpoint.params}
                body_dict[param_name] = payload
                parsed = urlparse(url)
                raw_req_preview = f"POST {url} HTTP/1.1\nHost: {parsed.netloc}\nContent-Type: application/x-www-form-urlencoded\nUser-Agent: Mozilla/5.0\n\n{urlencode(body_dict)}"
                
                resp = await client.post(
                    url,
                    data=body_dict,
                    headers=req_headers,
                    cookies=self.auth_cookies,
                    timeout=self.timeout
                )
            else:
                return None

            elapsed_ms = (time.time() - start_t) * 1000.0

            res_data = {
                "url": url,
                "method": method,
                "parameter": param_name,
                "payload_obj": payload_obj,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "text": resp.text,
                "elapsed_ms": elapsed_ms,
                "raw_request": raw_req_preview
            }
            if self.on_probe_executed:
                try:
                    self.on_probe_executed(res_data)
                except Exception:
                    pass
            return res_data
        except Exception as ex:
            err_data = {
                "url": url,
                "method": method,
                "parameter": param_name,
                "payload_obj": payload_obj,
                "error": str(ex),
                "raw_request": raw_req_preview
            }
            if self.on_probe_executed:
                try:
                    self.on_probe_executed(err_data)
                except Exception:
                    pass
            return err_data

    async def analyze_endpoint_parameter(
        self,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        client: httpx.AsyncClient
    ) -> List[Dict[str, Any]]:
        """
        Run differential testing across all vulnerability categories for a single parameter.
        """
        findings = []

        if self.stop_checker and self.stop_checker():
            return findings

        # 1. Fetch baseline
        try:
            if endpoint.method == "GET":
                base_resp = await client.get(endpoint.url, headers=self.auth_headers, cookies=self.auth_cookies, timeout=self.timeout)
            else:
                base_resp = await client.post(endpoint.url, data={}, headers=self.auth_headers, cookies=self.auth_cookies, timeout=self.timeout)
            baseline_status = base_resp.status_code
            baseline_len = len(base_resp.text)
        except Exception:
            baseline_status = 200
            baseline_len = 0

        # 2. Iterate through relevant probe categories
        for category, probe_list in PROBES.items():
            if self.stop_checker and self.stop_checker():
                break
            category_confirmed = False  # Break-on-first-confirm: once a vuln is confirmed for this category, skip remaining probes
            for probe_item in probe_list:
                if self.stop_checker and self.stop_checker():
                    break
                if category_confirmed:
                    break
                result = await self.execute_probe(client, endpoint, param_name, probe_item)
                if not result or "error" in result:
                    continue

                resp_text = result.get("text", "")
                resp_headers = result.get("headers", {})
                resp_status = result.get("status_code", 200)
                payload = probe_item["payload"]

                evidence = {
                    "probe_type": probe_item["type"],
                    "probe_description": probe_item["description"],
                    "payload_sent": payload,
                    "status_code": resp_status,
                    "baseline_status": baseline_status,
                    "baseline_len": baseline_len,
                    "response_len": len(resp_text),
                    "raw_request": result.get("raw_request")
                }

                # A. Check SQL Injection Errors
                if category == "SQL_Injection":
                    for pattern, db_name in SQL_ERROR_SIGNATURES:
                        if re.search(pattern, resp_text):
                            evidence["sql_error_matched"] = pattern
                            evidence["detected_db"] = db_name
                            evidence["snippet"] = resp_text[:300]
                            findings.append({
                                "vuln_type": "SQL_Injection",
                                "category": "Injection",
                                "severity": "HIGH",
                                "confidence": 94.5,
                                "status": "Confirmed",
                                "url": endpoint.url,
                                "parameter": param_name,
                                "http_method": endpoint.method,
                                "dynamic_analysis": evidence,
                                "raw_request": result.get("raw_request"),
                                "remediation": "Use parameterized SQL queries / prepared statements (e.g. cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))). Never concatenate user input directly into SQL commands."
                            })
                            category_confirmed = True
                            break

                # B. Check XSS Canary Reflection
                elif category == "Cross_Site_Scripting":
                    if f"<tcqcanary data='{CANARY_ID}'>" in resp_text or f"<tcqprobe>{CANARY_ID}</tcqprobe>" in resp_text:
                        evidence["canary_reflected"] = True
                        evidence["reflection_snippet"] = f"...{payload}..."
                        findings.append({
                            "vuln_type": "Cross_Site_Scripting",
                            "category": "XSS",
                            "severity": "HIGH",
                            "confidence": 96.0,
                            "status": "Confirmed",
                            "url": endpoint.url,
                            "parameter": param_name,
                            "http_method": endpoint.method,
                            "dynamic_analysis": evidence,
                            "raw_request": result.get("raw_request"),
                            "remediation": "Apply context-aware output encoding (HTML entity encoding, attribute escaping) and enforce Content-Security-Policy."
                        })
                        category_confirmed = True

                # C. Check Directory Traversal
                elif category == "Directory_Traversal":
                    for trav_pat in TRAVERSAL_INDICATORS:
                        if re.search(trav_pat, resp_text):
                            evidence["traversal_match"] = trav_pat
                            evidence["snippet"] = resp_text[:200]
                            findings.append({
                                "vuln_type": "Directory_Traversal",
                                "category": "File_Inclusion",
                                "severity": "CRITICAL",
                                "confidence": 98.0,
                                "status": "Confirmed",
                                "url": endpoint.url,
                                "parameter": param_name,
                                "http_method": endpoint.method,
                                "dynamic_analysis": evidence,
                                "raw_request": result.get("raw_request"),
                                "remediation": "Validate input against a strict whitelist of permitted file names. Strip path traversal sequences (../, ..\\) using os.path.basename and verify the resolved path stays within the authorized directory."
                            })
                            category_confirmed = True
                            break

                # D. Check SSTI Arithmetic Evaluation
                elif category == "Server_Side_Template_Injection":
                    expected = probe_item.get("expected_reflection")
                    if expected and expected in resp_text and payload not in resp_text:
                        evidence["calculated_result_reflected"] = expected
                        findings.append({
                            "vuln_type": "Server_Side_Template_Injection",
                            "category": "Injection",
                            "severity": "CRITICAL",
                            "confidence": 97.0,
                            "status": "Confirmed",
                            "url": endpoint.url,
                            "parameter": param_name,
                            "http_method": endpoint.method,
                            "dynamic_analysis": evidence,
                            "raw_request": result.get("raw_request"),
                            "remediation": "Never pass user-supplied input directly into template rendering engines (e.g. render_template_string). Pass values via context variables."
                        })
                        category_confirmed = True

                # E. Check Command Injection Output Reflection
                elif category == "Command_Injection":
                    if CANARY_ID in resp_text and payload not in resp_text:
                        evidence["command_echo_reflected"] = True
                        findings.append({
                            "vuln_type": "Command_Injection",
                            "category": "RCE",
                            "severity": "CRITICAL",
                            "confidence": 95.0,
                            "status": "Confirmed",
                            "url": endpoint.url,
                            "parameter": param_name,
                            "http_method": endpoint.method,
                            "dynamic_analysis": evidence,
                            "raw_request": result.get("raw_request"),
                            "remediation": "Avoid invoking shell processes (os.system, subprocess with shell=True). If external processes are necessary, use subprocess.run with argument arrays without shell expansion."
                        })
                        category_confirmed = True

                # F. Check CRLF Header Injection
                elif category == "CRLF_Injection":
                    for hk, hv in resp_headers.items():
                        if "x-tcq-probe" in hk.lower() or CANARY_ID in hv:
                            evidence["injected_header_found"] = f"{hk}: {hv}"
                            findings.append({
                                "vuln_type": "CRLF_Injection",
                                "category": "Header_Injection",
                                "severity": "MEDIUM",
                                "confidence": 95.0,
                                "status": "Confirmed",
                                "url": endpoint.url,
                                "parameter": param_name,
                                "http_method": endpoint.method,
                                "dynamic_analysis": evidence,
                                "raw_request": result.get("raw_request"),
                                "remediation": "Sanitize and strip carriage return (\\r, %0d) and newline (\\n, %0a) characters before including user input in HTTP response headers or cookie values."
                            })
                            category_confirmed = True
                            break

                # G. Check Open Redirect
                elif category == "Open_Redirect":
                    loc = resp_headers.get("location", "")
                    if "example.com/tcq-redirect-check" in loc:
                        evidence["redirect_location"] = loc
                        findings.append({
                            "vuln_type": "Open_Redirect",
                            "category": "Redirection",
                            "severity": "MEDIUM",
                            "confidence": 92.0,
                            "status": "Confirmed",
                            "url": endpoint.url,
                            "parameter": param_name,
                            "http_method": endpoint.method,
                            "dynamic_analysis": evidence,
                            "raw_request": result.get("raw_request"),
                            "remediation": "Validate target redirection URLs against a strict whitelist of internal relative paths or authorized target domains."
                        })
                        category_confirmed = True

                # H. Check Differential 500 Anomaly
                elif resp_status == 500 and baseline_status == 200:
                    evidence["differential_anomaly"] = "HTTP 500 internal server error triggered by probe"
                    findings.append({
                        "vuln_type": f"Potential_{category}",
                        "category": "Server_Error_Anomaly",
                        "severity": "LOW",
                        "confidence": 65.0,
                        "status": "Requires Verification",
                        "url": endpoint.url,
                        "parameter": param_name,
                        "http_method": endpoint.method,
                        "dynamic_analysis": evidence,
                        "raw_request": result.get("raw_request"),
                        "remediation": "Investigate unhandled exception logs on the backend server triggered by unexpected input characters."
                    })
                    category_confirmed = True

        return findings
