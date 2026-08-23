import pytest
import os
from backend.ml.predictor import MLVulnerabilityPredictor

def test_ml_model_loading_and_prediction():
    predictor = MLVulnerabilityPredictor.get_instance()
    assert predictor is not None
    
    # 1. Test SQL Injection sample
    sqli_req = "GET /vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271 HTTP/1.1\nHost: localhost:3000\nUser-Agent: Mozilla/5.0"
    res1 = predictor.predict_request(sqli_req)
    assert res1["is_anomalous"] is True
    assert "SQL" in res1["category"] or "Injection" in res1["category"]
    assert res1["confidence"] > 50.0

    # 2. Test Benign request
    normal_req = "GET / HTTP/1.1\nHost: localhost:3000\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\nAccept-Encoding: gzip, deflate, br\nAccept: */*\nConnection: keep-alive"
    res2 = predictor.predict_request(normal_req)
    assert res2["category"] == "Normal" or res2["is_anomalous"] is False

    # 3. Test XSS sample
    xss_req = "POST /comment HTTP/1.1\nHost: localhost:3000\nContent-Type: application/x-www-form-urlencoded\n\ncomment=%3Cscript%3Ealert(1)%3C/script%3E"
    res3 = predictor.predict_request(xss_req)
    assert res3["is_anomalous"] is True
    assert res3["confidence"] > 30.0
