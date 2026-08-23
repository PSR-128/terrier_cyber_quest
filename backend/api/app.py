"""
FastAPI Application Entrypoint for Cyber-Reasoning Platform.
Provides REST and WebSocket endpoints for real-time vulnerability discovery, cyber-reasoning,
automated patching, regression test verification, and report exporting.
Enforces IST timestamps and CVSS v4.0 standard.
"""

import os
import json
import asyncio
from fastapi import FastAPI, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from typing import Dict, Any, List, Set, Optional

from backend.api.schemas import (
    StartScanRequest, PatchGenerateRequest, PatchApplyRequest, RegressionVerifyRequest
)
from backend.database.db import ScanRepository, init_db
from backend.scanner.orchestrator import ScanOrchestrator
from backend.patching.patch_engine import StagingPatchEngine
from backend.regression.test_harness import RegressionTestHarness
from backend.reporting.pdf_generator import PDFReportGenerator
from backend.reporting.json_exporter import JSONExporter
from backend.utils.timezone import get_ist_iso

init_db()

app = FastAPI(
    title="Terrier Cyber Quest - AI Cyber-Reasoning Scanner",
    description="Autonomous AI-Powered Web Vulnerability Detection and Cyber-Reasoning Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections and scan tasks
active_websockets: Dict[str, Set[WebSocket]] = {}
active_scans: Dict[str, ScanOrchestrator] = {}
active_tasks: Dict[str, asyncio.Task] = {}


def broadcast_event(event_type: str, data: Dict[str, Any]):
    scan_id = data.get("scan_id")
    if scan_id and scan_id in active_websockets:
        payload = json.dumps({"event": event_type, "data": data})
        for ws in list(active_websockets[scan_id]):
            try:
                asyncio.create_task(ws.send_text(payload))
            except Exception:
                pass


async def run_orchestrated_scan_task(orchestrator: ScanOrchestrator):
    try:
        await orchestrator.run_scan()
    except asyncio.CancelledError:
        print(f"[Orchestrator] Scan {orchestrator.scan_id} task cancelled cleanly.")
    except Exception as e:
        print(f"[Orchestrator Error] Scan {orchestrator.scan_id} failed: {e}")
        ScanRepository.update_scan_status(orchestrator.scan_id, "FAILED", {"error": str(e)})
        broadcast_event("scan_failed", {"scan_id": orchestrator.scan_id, "error": str(e)})
    finally:
        active_tasks.pop(orchestrator.scan_id, None)
        active_scans.pop(orchestrator.scan_id, None)


@app.post("/api/scan/start")
async def start_scan(req: StartScanRequest):
    """Initiate an autonomous cyber-reasoning scan on an authorized target URL."""
    if not req.target_url or not req.target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="A valid HTTP/HTTPS URL must be provided.")

    orchestrator = ScanOrchestrator(
        target_url=req.target_url,
        scope_config=req.scope.dict() if req.scope else {},
        auth_config=req.auth.dict() if req.auth else {},
        on_event=broadcast_event
    )
    active_scans[orchestrator.scan_id] = orchestrator
    
    # Launch async task with immediate cancellation tracking
    task = asyncio.create_task(run_orchestrated_scan_task(orchestrator))
    active_tasks[orchestrator.scan_id] = task

    return {
        "status": "STARTED",
        "scan_id": orchestrator.scan_id,
        "target_url": req.target_url,
        "started_at": get_ist_iso(),
        "message": "Autonomous discovery and cyber-reasoning engine initialized."
    }


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    """Immediately terminate a running scan and cancel background worker tasks."""
    if scan_id in active_scans:
        orchestrator = active_scans[scan_id]
        orchestrator.stop()

    if scan_id in active_tasks:
        task = active_tasks[scan_id]
        if not task.done():
            task.cancel()
        active_tasks.pop(scan_id, None)

    active_scans.pop(scan_id, None)
    
    ScanRepository.update_scan_status(scan_id, "STOPPED", {"stopped_by_user": True})
    broadcast_event("scan_stopped", {
        "scan_id": scan_id,
        "message": "Scan process terminated immediately by user request.",
        "timestamp": get_ist_iso()
    })
    return {
        "status": "STOPPED",
        "scan_id": scan_id,
        "message": "Scan execution terminated and background tasks cancelled cleanly."
    }


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Retrieve full scan record with discovered endpoints, findings, and patches."""
    scan = ScanRepository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.get("/api/scans")
async def list_scans():
    """List historical scans."""
    return ScanRepository.list_scans()


@app.get("/api/scan/{scan_id}/export/pdf")
async def export_pdf(scan_id: str):
    """Generate and export a competition-grade PDF audit report with CVSS v4.0 scores."""
    scan = ScanRepository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    pdf_bytes = PDFReportGenerator.generate_report(scan)
    filename = f"cyber_quest_report_{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/scan/{scan_id}/export/json")
async def export_json(scan_id: str):
    """Export complete scan telemetry as JSON."""
    scan = ScanRepository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    json_str = JSONExporter.export_scan(scan)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=cyber_quest_scan_{scan_id[:8]}.json"}
    )


@app.post("/api/patch/generate")
async def generate_patch(req: PatchGenerateRequest):
    """Generate a structured, copyable patch and diff for a local staging file."""
    engine = StagingPatchEngine()
    result = engine.generate_patch(
        target_file_path=req.target_file,
        vuln_type=req.vuln_type,
        parameter_name=req.parameter
    )
    return result


@app.post("/api/patch/apply")
async def apply_patch(req: PatchApplyRequest):
    """Apply generated patch to the local staging copy."""
    engine = StagingPatchEngine()
    result = engine.apply_patch(req.target_file, req.patched_code)
    
    if result.get("success"):
        # Save patch record in DB
        patch_id = f"patch_{req.finding_id[:8]}"
        ScanRepository.record_patch({
            "id": patch_id,
            "scan_id": req.scan_id,
            "finding_id": req.finding_id,
            "target_file": req.target_file,
            "patched_code": req.patched_code,
            "patch_status": "APPLIED",
            "regression_status": "PENDING_VERIFICATION"
        })
    return result


@app.post("/api/patch/verify")
async def verify_patch(req: RegressionVerifyRequest):
    """Execute regression test harness against patched endpoint to verify remediation with evidence."""
    scan = ScanRepository.get_scan(req.scan_id)
    auth_headers = scan.get("auth_config", {}).get("headers", {}) if scan else {}
    auth_cookies = scan.get("auth_config", {}).get("cookies", {}) if scan else {}
    
    # Locate finding
    finding = next((f for f in (scan.get("findings", []) if scan else []) if f.get("id") == req.finding_id), {})

    harness = RegressionTestHarness(auth_headers=auth_headers, auth_cookies=auth_cookies)
    result = await harness.verify_fix(
        finding=finding,
        endpoint_url=req.endpoint_url,
        http_method=req.http_method,
        parameter_name=req.parameter
    )

    # Update patch record
    patch_id = f"patch_{req.finding_id[:8]}"
    ScanRepository.record_patch({
        "id": patch_id,
        "scan_id": req.scan_id,
        "finding_id": req.finding_id,
        "target_file": finding.get("parameter", "staging_file"),
        "patch_status": "APPLIED",
        "regression_status": result.get("verdict"),
        "regression_details": result
    })

    return result


@app.get("/api/model/info")
async def get_model_info():
    """Retrieve pre-trained model evaluation metrics and canonical classes."""
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "models")
    for fname in ["unified_eval_report.json", "eval_report.json"]:
        p = os.path.join(models_dir, fname)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
    return {"status": "Model training in progress or not yet exported"}


@app.websocket("/api/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """Live WebSocket stream for scan telemetry, discovered surfaces, and real-time findings."""
    await websocket.accept()
    if scan_id not in active_websockets:
        active_websockets[scan_id] = set()
    active_websockets[scan_id].add(websocket)

    try:
        # Send initial snapshot if scan already exists
        scan = ScanRepository.get_scan(scan_id)
        if scan:
            await websocket.send_text(json.dumps({"event": "initial_state", "data": scan}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if scan_id in active_websockets:
            active_websockets[scan_id].discard(websocket)


# Mount frontend directory for static UI serving
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
