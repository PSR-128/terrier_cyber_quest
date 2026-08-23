import pytest
import asyncio
import httpx
import os
from backend.scanner.orchestrator import ScanOrchestrator
from backend.database.db import ScanRepository
from backend.reporting.pdf_generator import PDFReportGenerator
from backend.reporting.json_exporter import JSONExporter
from backend.patching.patch_engine import StagingPatchEngine
from backend.regression.test_harness import RegressionTestHarness
from sample_vulnerable_app.app import app as staging_app
import uvicorn
import threading
import time

@pytest.fixture(scope="module")
def staging_server():
    # Run staging server in a background thread
    server = uvicorn.Server(uvicorn.Config(staging_app, host="127.0.0.1", port=5000, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    time.sleep(1.5)
    yield "http://127.0.0.1:5000"
    server.should_exit = True

@pytest.mark.asyncio
async def test_end_to_end_scan_and_reporting(staging_server):
    target_url = staging_server
    
    events_captured = []
    def event_handler(evt, data):
        events_captured.append((evt, data))

    orchestrator = ScanOrchestrator(
        target_url=target_url,
        scope_config={"max_depth": 2, "max_pages": 15},
        on_event=event_handler
    )

    # 1. Run Autonomous Scan
    scan_result = await orchestrator.run_scan()
    assert scan_result is not None
    assert scan_result["status"] == "COMPLETED"
    
    # 2. Verify Endpoints Discovered
    endpoints = scan_result.get("endpoints", [])
    assert len(endpoints) >= 4
    discovered_urls = [ep["url"] for ep in endpoints]
    assert any("/search" in u for u in discovered_urls)
    assert any("/greet" in u for u in discovered_urls)
    assert any("/view" in u for u in discovered_urls)

    # 3. Verify Findings & Cyber Reasoning
    findings = scan_result.get("findings", [])
    assert len(findings) >= 3
    vuln_types = [f["vuln_type"] for f in findings]
    assert any("SQL" in vt for vt in vuln_types)
    assert any("Cross_Site_Scripting" in vt or "XSS" in vt for vt in vuln_types)
    
    # Check that cyber-reasoning commentary was generated
    for f in findings:
        assert len(f.get("llm_reasoning", "")) > 0
        assert f.get("confidence", 0) > 50.0
        assert f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    # 4. Test PDF Report Generation
    pdf_bytes = PDFReportGenerator.generate_report(scan_result)
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")

    # 5. Test JSON Export
    json_str = JSONExporter.export_scan(scan_result)
    assert "findings" in json_str
    assert "endpoints" in json_str

    # 6. Test Staging Patch Generation & Regression Verification
    sqli_finding = next((f for f in findings if "SQL" in f.get("vuln_type", "")), None)
    if sqli_finding:
        patch_engine = StagingPatchEngine()
        target_file = os.path.join("sample_vulnerable_app", "app.py")
        patch_res = patch_engine.generate_patch(
            target_file_path=target_file,
            vuln_type=sqli_finding["vuln_type"],
            parameter_name=sqli_finding["parameter"]
        )
        assert patch_res["success"] is True
        assert "diff_text" in patch_res

        # Test regression harness execution
        harness = RegressionTestHarness()
        reg_result = await harness.verify_fix(
            finding=sqli_finding,
            endpoint_url=sqli_finding["url"],
            http_method=sqli_finding["http_method"],
            parameter_name=sqli_finding["parameter"]
        )
        assert "verdict" in reg_result
