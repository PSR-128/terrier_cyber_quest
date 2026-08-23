import pytest
from backend.llm.reasoning_engine import CyberReasoningEngine, GeminiReasoningClient

def test_gemini_reasoning_client_structure():
    engine = CyberReasoningEngine()
    
    ml_pred = {
        "is_anomalous": True,
        "category": "SQL_Injection",
        "confidence": 98.5
    }
    dynamic_evidence = {
        "sql_error_matched": "sqlite3.OperationalError: near syntax error",
        "detected_db": "SQLite"
    }

    finding = engine.synthesize_finding(
        endpoint_url="http://127.0.0.1:5000/search",
        http_method="GET",
        parameter_name="username",
        ml_prediction=ml_pred,
        dynamic_evidence=dynamic_evidence
    )

    assert "brief_info" in finding
    assert "exact_location" in finding
    assert "brief_remediation" in finding
    assert "GET http://127.0.0.1:5000/search" in finding["exact_location"] or "search" in finding["exact_location"]
    assert len(finding["brief_remediation"]) > 0
