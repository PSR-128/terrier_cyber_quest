"""
Database storage module for Scans, Endpoints, Vulnerability Findings, Patches, and Regression Tests.
Uses SQLite with structured JSON fields for rich audit trails and scan history.
All timestamps are recorded in Indian Standard Time (IST, UTC+05:30).
"""

import os
import json
import sqlite3
from typing import Dict, Any, List, Optional
from backend.utils.timezone import get_ist_iso, format_ist_display

DB_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(DB_DIR, "scans.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Scans table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        status TEXT NOT NULL,
        scope_config TEXT,
        auth_config TEXT,
        started_at TEXT,
        completed_at TEXT,
        summary TEXT,
        created_at TEXT
    )
    """)
    
    # Discovered Endpoints table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        url TEXT NOT NULL,
        method TEXT NOT NULL,
        params TEXT,
        headers TEXT,
        discovered_via TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    """)
    
    # Findings table (supporting CVSS v4.0 metrics and IST timestamps)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        vuln_type TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL DEFAULT 0.0,
        cvss_vector TEXT,
        cvss_v4 TEXT,
        confidence REAL NOT NULL,
        status TEXT NOT NULL,
        url TEXT NOT NULL,
        parameter TEXT,
        http_method TEXT NOT NULL,
        brief_info TEXT,
        exact_location TEXT,
        brief_remediation TEXT,
        evidence TEXT,
        ml_prediction TEXT,
        static_analysis TEXT,
        dynamic_analysis TEXT,
        llm_reasoning TEXT,
        remediation TEXT,
        uncertainty_warning TEXT,
        created_at TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    """)
    
    # Check if columns exist in existing db and alter if needed
    cursor.execute("PRAGMA table_info(findings)")
    existing_cols = [row["name"] for row in cursor.fetchall()]
    for col, col_type in [
        ("cvss_score", "REAL DEFAULT 0.0"),
        ("cvss_vector", "TEXT"),
        ("cvss_v4", "TEXT"),
        ("brief_info", "TEXT"),
        ("exact_location", "TEXT"),
        ("brief_remediation", "TEXT")
    ]:
        if col not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE findings ADD COLUMN {col} {col_type}")
            except Exception:
                pass

    # Patches and Regression Tests table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS patches (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        target_file TEXT NOT NULL,
        original_code TEXT,
        patched_code TEXT,
        diff_text TEXT,
        clean_patch_snippet TEXT,
        remediation_notes TEXT,
        patch_status TEXT NOT NULL,
        regression_status TEXT,
        regression_details TEXT,
        created_at TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id),
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    )
    """)

    cursor.execute("PRAGMA table_info(patches)")
    existing_p_cols = [row["name"] for row in cursor.fetchall()]
    for col, col_type in [
        ("clean_patch_snippet", "TEXT"),
        ("remediation_notes", "TEXT")
    ]:
        if col not in existing_p_cols:
            try:
                cursor.execute(f"ALTER TABLE patches ADD COLUMN {col} {col_type}")
            except Exception:
                pass
    
    conn.commit()
    conn.close()


init_db()


class ScanRepository:
    @staticmethod
    def create_scan(scan_id: str, target_url: str, scope_config: Dict[str, Any], auth_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        now = get_ist_iso()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO scans (id, target_url, status, scope_config, auth_config, started_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target_url, "RUNNING", json.dumps(scope_config), json.dumps(auth_config or {}), now, now)
        )
        conn.commit()
        conn.close()
        return {"id": scan_id, "target_url": target_url, "status": "RUNNING", "started_at": now}

    @staticmethod
    def update_scan_status(scan_id: str, status: str, summary: Optional[Dict[str, Any]] = None):
        now = get_ist_iso()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scans SET status = ?, completed_at = ?, summary = ? WHERE id = ?",
            (status, now, json.dumps(summary or {}), scan_id)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def add_endpoint(scan_id: str, url: str, method: str, params: Any, headers: Any, discovered_via: str = "crawler"):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO endpoints (scan_id, url, method, params, headers, discovered_via) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, url, method, json.dumps(params), json.dumps(headers), discovered_via)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def add_finding(finding: Dict[str, Any]):
        now = get_ist_iso()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT OR REPLACE INTO findings (
            id, scan_id, vuln_type, category, severity, cvss_score, cvss_vector, cvss_v4,
            confidence, status, url, parameter, http_method, brief_info, exact_location,
            brief_remediation, evidence, ml_prediction, static_analysis, dynamic_analysis,
            llm_reasoning, remediation, uncertainty_warning, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.get("id"),
            finding.get("scan_id"),
            finding.get("vuln_type"),
            finding.get("category", "General"),
            finding.get("severity", "MEDIUM"),
            finding.get("cvss_score", 0.0),
            finding.get("cvss_vector", ""),
            json.dumps(finding.get("cvss_v4", {})),
            finding.get("confidence", 0.0),
            finding.get("status", "Requires Verification"),
            finding.get("url"),
            finding.get("parameter"),
            finding.get("http_method", "GET"),
            finding.get("brief_info", ""),
            finding.get("exact_location", ""),
            finding.get("brief_remediation", ""),
            json.dumps(finding.get("evidence", {})),
            json.dumps(finding.get("ml_prediction", {})),
            json.dumps(finding.get("static_analysis", {})),
            json.dumps(finding.get("dynamic_analysis", {})),
            finding.get("llm_reasoning", ""),
            finding.get("remediation", ""),
            finding.get("uncertainty_warning", ""),
            finding.get("detected_at") or now
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def record_patch(patch_data: Dict[str, Any]):
        now = get_ist_iso()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT OR REPLACE INTO patches (
            id, scan_id, finding_id, target_file, original_code, patched_code, diff_text,
            clean_patch_snippet, remediation_notes, patch_status, regression_status, regression_details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            patch_data.get("id"),
            patch_data.get("scan_id"),
            patch_data.get("finding_id"),
            patch_data.get("target_file"),
            patch_data.get("original_code"),
            patch_data.get("patched_code"),
            patch_data.get("diff_text"),
            patch_data.get("clean_patch_snippet", ""),
            patch_data.get("remediation_notes", ""),
            patch_data.get("patch_status", "GENERATED"),
            patch_data.get("regression_status", "UNVERIFIED"),
            json.dumps(patch_data.get("regression_details", {})),
            now
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            conn.close()
            return None

        scan_dict = dict(scan_row)
        scan_dict["scope_config"] = json.loads(scan_dict.get("scope_config") or "{}")
        scan_dict["auth_config"] = json.loads(scan_dict.get("auth_config") or "{}")
        scan_dict["summary"] = json.loads(scan_dict.get("summary") or "{}")

        # Fetch endpoints
        cursor.execute("SELECT * FROM endpoints WHERE scan_id = ?", (scan_id,))
        endpoints = []
        for ep in cursor.fetchall():
            ep_dict = dict(ep)
            ep_dict["params"] = json.loads(ep_dict.get("params") or "[]")
            ep_dict["headers"] = json.loads(ep_dict.get("headers") or "{}")
            endpoints.append(ep_dict)
        scan_dict["endpoints"] = endpoints

        # Fetch findings
        cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        findings = []
        for f in cursor.fetchall():
            f_dict = dict(f)
            f_dict["evidence"] = json.loads(f_dict.get("evidence") or "{}")
            f_dict["ml_prediction"] = json.loads(f_dict.get("ml_prediction") or "{}")
            f_dict["static_analysis"] = json.loads(f_dict.get("static_analysis") or "{}")
            f_dict["dynamic_analysis"] = json.loads(f_dict.get("dynamic_analysis") or "{}")
            f_dict["cvss_v4"] = json.loads(f_dict.get("cvss_v4") or "{}")
            findings.append(f_dict)
        scan_dict["findings"] = findings

        # Fetch patches
        cursor.execute("SELECT * FROM patches WHERE scan_id = ?", (scan_id,))
        patches = []
        for p in cursor.fetchall():
            p_dict = dict(p)
            p_dict["regression_details"] = json.loads(p_dict.get("regression_details") or "{}")
            patches.append(p_dict)
        scan_dict["patches"] = patches

        conn.close()
        return scan_dict

    @staticmethod
    def list_scans() -> List[Dict[str, Any]]:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT s.*, 
               (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as finding_count,
               (SELECT COUNT(*) FROM endpoints e WHERE e.scan_id = s.id) as endpoint_count
        FROM scans s
        ORDER BY s.started_at DESC
        """)
        scans = []
        for r in cursor.fetchall():
            d = dict(r)
            d["summary"] = json.loads(d.get("summary") or "{}")
            d["started_at_display"] = format_ist_display(d.get("started_at"))
            d["completed_at_display"] = format_ist_display(d.get("completed_at")) if d.get("completed_at") else None
            scans.append(d)
        conn.close()
        return scans
