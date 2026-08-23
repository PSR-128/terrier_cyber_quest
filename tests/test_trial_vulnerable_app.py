"""
Test Suite for the Trial Vulnerable Web Application.
Validates:
- CVSS 4.0 severity alignment (2 Critical, 2 High, 2 Medium, 2 Low)
- Correct response behavior for all vulnerable endpoints
- Source code viewer accessibility via HTML and REST API
- Seamless integration with the static and dynamic analysis engines
"""

import pytest
from fastapi.testclient import TestClient
from trial_vulnerable_app.app import app
from backend.cvss.cvss_v4 import compute_cvss_v4
from backend.static_analysis.static_engine import StaticAnalysisEngine


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    """Verify application health and configuration."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["vulnerabilities_configured"] == 8
    assert data["cvss_version"] == "4.0"


# =====================================================================
# CVSS 4.0 SEVERITY MAPPING TESTS
# =====================================================================

def test_cvss_4_severity_distribution():
    """Ensure exactly 2 vulnerabilities exist for each CVSS 4.0 severity tier."""
    vulns = [
        # Critical (2)
        ("Command_Injection", "CRITICAL", 10.0),
        ("SQL_Injection", "CRITICAL", 9.3),
        # High (2)
        ("Directory_Traversal", "HIGH", 8.7),
        ("Server_Side_Request_Forgery", "HIGH", 8.7),
        # Medium (2)
        ("Cross_Site_Scripting", "MEDIUM", 6.9),
        ("Open_Redirect", "MEDIUM", 5.1),
        # Low (2)
        ("Missing_Security_Header", "LOW", 2.3),
        ("HTML_Comments_Disclosure", "LOW", 3.1)  # Low severity info disclosure
    ]

    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for name, expected_tier, min_score in vulns:
        res = compute_cvss_v4(name, status="Confirmed")
        assert res["vector"].startswith("CVSS:4.0/")
        assert res["severity"] == expected_tier
        # Count tiers
        score = res["score"]
        if score >= 9.0:
            tier_counts["CRITICAL"] += 1
        elif score >= 7.0:
            tier_counts["HIGH"] += 1
        elif score >= 4.0:
            tier_counts["MEDIUM"] += 1
        else:
            tier_counts["LOW"] += 1

    # Check > 1 and < 3 (strictly 2 each)
    assert tier_counts["CRITICAL"] == 2
    assert tier_counts["HIGH"] == 2
    assert tier_counts["MEDIUM"] == 2
    assert tier_counts["LOW"] == 2


# =====================================================================
# SOURCE CODE ACCESS TESTS
# =====================================================================

def test_source_code_html_page(client):
    """Verify in-browser source code viewer is accessible."""
    response = client.get("/source")
    assert response.status_code == 200
    assert "Source Code Explorer" in response.text
    assert "app.py" in response.text


def test_source_code_api_endpoint(client):
    """Verify REST API returns readable source code files."""
    # 1. Fetch app.py
    resp = client.get("/api/source?file=app.py")
    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "app.py"
    assert "Trial Vulnerable Web Application" in data["content"]
    assert data["line_count"] > 50

    # 2. Fetch index.html
    resp = client.get("/api/source?file=index.html")
    assert resp.status_code == 200
    assert "Trial Vulnerable Web Application" in resp.json()["content"]

    # 3. Denied unauthorized file
    resp = client.get("/api/source?file=unauthorized.py")
    assert resp.status_code == 400


# =====================================================================
# CRITICAL VULNERABILITY ENDPOINT TESTS
# =====================================================================

def test_critical_command_injection(client):
    """Verify Command Injection endpoint (/api/tools/ping)."""
    # Probe with canary ID
    response = client.post("/api/tools/ping", data={"host": "127.0.0.1; echo tcq_audit_probe;"})
    assert response.status_code == 200
    assert "tcq_audit_probe" in response.text


def test_critical_sql_injection(client):
    """Verify SQL Injection endpoint (/api/users/search)."""
    # Normal query
    resp_norm = client.get("/api/users/search?username=alice")
    assert resp_norm.status_code == 200
    assert "alice@trial-company.internal" in resp_norm.text

    # Syntax error triggering SQLite exception
    resp_err = client.get("/api/users/search?username=' OR syntax error")
    assert resp_err.status_code == 500
    assert "sqlite3.OperationalError" in resp_err.text


# =====================================================================
# HIGH VULNERABILITY ENDPOINT TESTS
# =====================================================================

def test_high_path_traversal(client):
    """Verify Path Traversal endpoint (/api/files/view)."""
    # Read sample file
    resp = client.get("/api/files/view?file=sample.txt")
    assert resp.status_code == 200
    assert "Trial Staging File Repository active" in resp.text

    # Read traverse canary
    resp_trav = client.get("/api/files/view?file=../../../../etc/passwd")
    assert resp_trav.status_code == 200
    assert "root:x:0:0" in resp_trav.text


def test_high_ssrf(client):
    """Verify SSRF endpoint (/api/proxy/fetch)."""
    response = client.post("/api/proxy/fetch", data={"target_url": "http://127.0.0.1:80/"})
    assert response.status_code == 200
    assert "SSRF Response from Internal Node" in response.text


# =====================================================================
# MEDIUM VULNERABILITY ENDPOINT TESTS
# =====================================================================

def test_medium_reflected_xss(client):
    """Verify Reflected XSS endpoint (/greet)."""
    probe_payload = "<tcqcanary data='tcq_audit_probe'>"
    response = client.get(f"/greet?name={probe_payload}")
    assert response.status_code == 200
    assert probe_payload in response.text


def test_medium_open_redirect(client):
    """Verify Open Redirect endpoint (/redirect)."""
    target = "https://example.com/tcq-redirect-check"
    response = client.get(f"/redirect?url={target}", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == target


# =====================================================================
# LOW VULNERABILITY ENDPOINT & STATIC AUDIT TESTS
# =====================================================================

def test_low_missing_security_headers(client):
    """Verify HTTP responses omit defensive security headers."""
    response = client.get("/")
    assert "Content-Security-Policy" not in response.headers
    assert "X-Frame-Options" not in response.headers
    assert "X-Content-Type-Options" not in response.headers


def test_low_static_information_disclosure(client):
    """Verify static analysis detects exposed comments and credentials."""
    response = client.get("/")
    static_engine = StaticAnalysisEngine()
    findings = static_engine.analyze_html_and_scripts(response.text, "http://127.0.0.1:5050/")
    
    # Should detect the comment / API key
    comment_findings = [f for f in findings if f["category"] in ["HTML_Comments", "Client_Side_Exposure"]]
    assert len(comment_findings) >= 1
