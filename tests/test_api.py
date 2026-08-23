import pytest
from fastapi.testclient import TestClient
from backend.api.app import app

client = TestClient(app)

def test_api_scans_list():
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

def test_api_model_info():
    resp = client.get("/api/model/info")
    assert resp.status_code == 200

def test_api_start_scan_invalid_url():
    resp = client.post("/api/scan/start", json={"target_url": "ftp://invalid"})
    assert resp.status_code == 400
