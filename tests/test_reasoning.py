import pytest
from backend.llm.reasoning_engine import CyberReasoningEngine

def test_reasoning_engine_confirmed_finding():
    engine = CyberReasoningEngine()
    
    ml_pred = {
        "is_anomalous": True,
        "category": "SQL_Injection",
        "confidence": 95.0
    }
    dynamic_evidence = {
        "sql_error_matched": "sqlite3.OperationalError",
        "detected_db": "SQLite",
        "status_code": 500
    }
    
    verdict = engine.synthesize_finding(
        endpoint_url="http://127.0.0.1:5000/search",
        http_method="GET",
        parameter_name="username",
        ml_prediction=ml_pred,
        dynamic_evidence=dynamic_evidence
    )
    
    assert verdict["vuln_type"] == "SQL_Injection"
    assert verdict["status"] == "Confirmed"
    assert verdict["confidence"] >= 95.0
    assert verdict["cvss_score"] >= 9.0
    assert verdict["severity"] == "CRITICAL"
    assert "CVSS:4.0" in verdict["cvss_vector"]
    assert "sqlite3.OperationalError" in verdict["llm_reasoning"]

def test_reasoning_engine_uncertain_finding():
    engine = CyberReasoningEngine()
    
    ml_pred = {
        "is_anomalous": True,
        "category": "Command_Injection",
        "confidence": 78.0
    }
    # No dynamic reflection
    dynamic_evidence = {
        "status_code": 200,
        "baseline_status": 200
    }
    
    verdict = engine.synthesize_finding(
        endpoint_url="http://127.0.0.1:5000/ping",
        http_method="POST",
        parameter_name="host",
        ml_prediction=ml_pred,
        dynamic_evidence=dynamic_evidence
    )
    
    assert verdict["status"] == "Requires Verification"
    assert len(verdict["uncertainty_warning"]) > 0
