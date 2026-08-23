import pytest
from backend.cvss.cvss_v4 import compute_cvss_v4, get_severity_from_score

def test_cvss_v4_severity_ranges():
    assert get_severity_from_score(0.0) == "NONE"
    assert get_severity_from_score(2.5) == "LOW"
    assert get_severity_from_score(3.9) == "LOW"
    assert get_severity_from_score(4.0) == "MEDIUM"
    assert get_severity_from_score(6.9) == "MEDIUM"
    assert get_severity_from_score(7.0) == "HIGH"
    assert get_severity_from_score(8.9) == "HIGH"
    assert get_severity_from_score(9.0) == "CRITICAL"
    assert get_severity_from_score(10.0) == "CRITICAL"

def test_cvss_v4_command_injection():
    res = compute_cvss_v4("Command_Injection", "Confirmed")
    assert res["score"] == 10.0
    assert res["severity"] == "CRITICAL"
    assert "CVSS:4.0" in res["vector"]
    assert "exploitability" in res
    assert "impact" in res

def test_cvss_v4_sql_injection():
    res = compute_cvss_v4("SQL_Injection", "Confirmed")
    assert res["score"] == 9.3
    assert res["severity"] == "CRITICAL"
    assert res["vector"].startswith("CVSS:4.0/")

def test_cvss_v4_xss():
    res = compute_cvss_v4("Cross_Site_Scripting", "Confirmed")
    assert res["score"] == 6.9
    assert res["severity"] == "MEDIUM"

def test_cvss_v4_missing_headers():
    res = compute_cvss_v4("Missing_Security_Header", "Confirmed")
    assert res["score"] == 2.3
    assert res["severity"] == "LOW"
