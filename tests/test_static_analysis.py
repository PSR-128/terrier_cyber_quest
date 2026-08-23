import pytest
from backend.static_analysis.static_engine import StaticAnalysisEngine

def test_missing_security_headers():
    engine = StaticAnalysisEngine()
    # Headers missing CSP and HSTS
    headers = {"Content-Type": "text/html; charset=utf-8"}
    findings = engine.analyze_headers(headers, "http://127.0.0.1:5000/")
    
    types = [f["vuln_type"] for f in findings]
    assert "Missing_Security_Header" in types
    params = [f["parameter"] for f in findings]
    assert "Content-Security-Policy" in params

def test_client_side_secret_detection():
    engine = StaticAnalysisEngine()
    html_with_secret = """
    <html>
      <head><title>Test Page</title></head>
      <body>
        <script>
          const apiKey = "AIzaSyD918374918237498172398471928374918";
        </script>
        <!-- TODO: admin password is supersecret -->
      </body>
    </html>
    """
    findings = engine.analyze_html_and_scripts(html_with_secret, "http://127.0.0.1:5000/")
    assert len(findings) >= 2
    types = [f["vuln_type"] for f in findings]
    assert "Information_Disclosure" in types
