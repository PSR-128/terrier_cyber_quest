"""
Master Scanner Orchestrator with Dynamic ETA and CVSS v4.0 Classification.
Coordinates the end-to-end autonomous cyber-reasoning security testing pipeline:
Scope -> Crawl -> Static Analysis -> Dynamic Differential Fuzzing -> ML Scoring -> Cyber-Reasoning -> Persistence.
Includes dynamic ETA calculation, duplicate-free crawling, and immediate process termination.
"""

import time
import uuid
import hashlib
import asyncio
import httpx
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Callable, Tuple
from backend.crawler.scope import ScopeController, normalize_url
from backend.crawler.crawler import WebCrawler, DiscoveredEndpoint
from backend.static_analysis.static_engine import StaticAnalysisEngine
from backend.dynamic_analysis.dynamic_engine import DynamicAnalysisEngine
from backend.ml.predictor import MLVulnerabilityPredictor
from backend.llm.reasoning_engine import CyberReasoningEngine
from backend.database.db import ScanRepository
from backend.utils.timezone import get_ist_iso, format_ist_display
from backend.fuzzing.payload_generator import PROBES


class ScanOrchestrator:
    def __init__(
        self,
        target_url: str,
        scope_config: Optional[Dict[str, Any]] = None,
        auth_config: Optional[Dict[str, Any]] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None
    ):
        self.scan_id = str(uuid.uuid4())
        self.target_url = normalize_url(target_url) or target_url
        self.scope_config = scope_config or {}
        self.auth_config = auth_config or {}
        self.on_event = on_event
        self.is_stopped = False
        self.total_requests_sent = 0
        self.start_timestamp = time.time()
        
        # Progress tracking for ETA
        self.total_probes_estimated = 0
        self.probes_completed = 0
        self.fuzz_start_time: Optional[float] = None
        self.pages_crawled = 0

        self.scope = ScopeController(
            target_url=self.target_url,
            allowed_domains=self.scope_config.get("allowed_domains"),
            allow_subdomains=self.scope_config.get("allow_subdomains", True),
            max_depth=self.scope_config.get("max_depth", 3),
            max_pages=self.scope_config.get("max_pages", 30),
            max_duration_sec=self.scope_config.get("max_duration_sec", 180)
        )

        auth_headers = self.auth_config.get("headers", {})
        auth_cookies = self.auth_config.get("cookies", {})
        if self.auth_config.get("bearer_token"):
            auth_headers["Authorization"] = f"Bearer {self.auth_config['bearer_token']}"

        self.crawler = WebCrawler(
            scope=self.scope,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            on_progress=self._crawler_progress_handler,
            stop_checker=lambda: self.is_stopped
        )
        self.static_engine = StaticAnalysisEngine(auth_headers=auth_headers)
        self.dynamic_engine = DynamicAnalysisEngine(
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            stop_checker=lambda: self.is_stopped,
            on_probe_executed=self._probe_executed_handler
        )
        self.ml_predictor = MLVulnerabilityPredictor.get_instance()
        gemini_key = self.auth_config.get("gemini_api_key")
        self.reasoning_engine = CyberReasoningEngine(gemini_api_key=gemini_key)

        self.findings: List[Dict[str, Any]] = []
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self._seen_fingerprints: Dict[str, Dict[str, Any]] = {}  # fingerprint -> best finding

        # Initialize scan in database with IST timestamp
        ScanRepository.create_scan(
            scan_id=self.scan_id,
            target_url=self.target_url,
            scope_config=self.scope_config,
            auth_config=self.auth_config
        )

    def stop(self):
        """Immediately terminate the running scan and release resources."""
        self.is_stopped = True
        ScanRepository.update_scan_status(self.scan_id, "STOPPED", {
            "duration_sec": round(time.time() - self.start_timestamp, 2),
            "total_findings": len(self.findings),
            "total_requests": self.total_requests_sent,
            "stopped_by_user": True
        })
        self._emit("scan_stopped", {
            "scan_id": self.scan_id,
            "message": "Scan execution terminated by user request.",
            "total_findings": len(self.findings),
            "endpoints_scanned": len(self.discovered_endpoints),
            "timestamp": get_ist_iso()
        })

    def _emit(self, event_type: str, data: Dict[str, Any]):
        if self.on_event:
            try:
                self.on_event(event_type, {
                    "scan_id": self.scan_id,
                    "timestamp": get_ist_iso(),
                    **data
                })
            except Exception:
                pass

    def _compute_fingerprint(self, vuln_type: str, url: str, parameter: str) -> str:
        """
        Compute a stable fingerprint for a vulnerability based on its semantic identity.
        Same (normalized_url_path, vuln_type, normalized_parameter) = same vulnerability.
        Server-wide config issues (Missing_Security_Header) use origin-only so they
        deduplicate across different endpoint paths on the same server.
        """
        parsed = urlparse(url)
        # For server-wide config issues, use only scheme+host (no path)
        server_wide_types = {"Missing_Security_Header", "Insecure_CORS_Policy"}
        if vuln_type in server_wide_types:
            norm_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            # Use scheme + host + path (strip query string and fragments)
            norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"

        norm_param = (parameter or "").strip().lower()
        raw = f"{norm_url}|{vuln_type}|{norm_param}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _record_finding(self, verdict: Dict[str, Any]) -> bool:
        """
        Record a finding if it is not a duplicate. If a duplicate fingerprint exists,
        keep whichever finding has higher confidence (better evidence).
        Returns True if the finding was recorded (new or replaced), False if suppressed.
        """
        vuln_type = verdict.get("vuln_type", "Unknown")
        url = verdict.get("url", "")
        parameter = verdict.get("parameter", "")
        fp = self._compute_fingerprint(vuln_type, url, parameter)

        existing = self._seen_fingerprints.get(fp)
        if existing is None:
            # New unique finding
            verdict["id"] = str(uuid.uuid4())
            verdict["scan_id"] = self.scan_id
            verdict["_fingerprint"] = fp
            self._seen_fingerprints[fp] = verdict
            self.findings.append(verdict)
            ScanRepository.add_finding(verdict)
            self._emit("finding_detected", verdict)
            return True
        else:
            # Duplicate — keep higher confidence
            new_conf = float(verdict.get("confidence", 0))
            old_conf = float(existing.get("confidence", 0))
            if new_conf > old_conf:
                # Replace the old finding with the better one
                verdict["id"] = existing["id"]  # preserve original ID
                verdict["scan_id"] = self.scan_id
                verdict["_fingerprint"] = fp
                self._seen_fingerprints[fp] = verdict
                # Replace in the findings list
                for i, f in enumerate(self.findings):
                    if f.get("_fingerprint") == fp:
                        self.findings[i] = verdict
                        break
            return False

    def _calculate_eta(self) -> Tuple[Optional[float], str]:
        """
        Calculate dynamic Estimated Time Remaining (ETA).
        Returns: (seconds_remaining, formatted_display_str)
        """
        # If just started or stopped, show Calculating...
        elapsed_total = time.time() - self.start_timestamp
        if elapsed_total < 3.0 or self.is_stopped:
            return None, "Calculating..."

        if self.fuzz_start_time and self.total_probes_estimated > 0:
            # Dynamic probing stage ETA
            fuzz_elapsed = time.time() - self.fuzz_start_time
            if self.probes_completed < 3:
                return None, "Calculating..."
            
            avg_per_probe = fuzz_elapsed / max(1, self.probes_completed)
            remaining_probes = max(0, self.total_probes_estimated - self.probes_completed)
            remaining_sec = round(remaining_probes * avg_per_probe)
            
            if remaining_sec <= 0:
                return 0, "< 5s remaining"
            elif remaining_sec < 60:
                return remaining_sec, f"{remaining_sec}s remaining"
            else:
                mins = remaining_sec // 60
                secs = remaining_sec % 60
                return remaining_sec, f"{mins}m {secs}s remaining"

        # During crawling stage
        if self.pages_crawled < 2:
            return None, "Calculating..."
        
        avg_per_page = elapsed_total / max(1, self.pages_crawled)
        # Estimate remaining crawl pages (up to max_pages)
        est_remaining_pages = max(1, min(self.scope.max_pages - self.pages_crawled, 10))
        # Add baseline dynamic probe estimate
        est_sec = round(est_remaining_pages * avg_per_page + 15)
        if est_sec < 60:
            return est_sec, f"{est_sec}s remaining"
        mins = est_sec // 60
        secs = est_sec % 60
        return est_sec, f"{mins}m {secs}s remaining"

    def _crawler_progress_handler(self, evt: str, data: Dict[str, Any]):
        self.total_requests_sent += 1
        if evt == "crawl_page":
            self.pages_crawled += 1
        
        _, eta_str = self._calculate_eta()
        self._emit(f"crawler_{evt}", {
            **data,
            "total_requests": self.total_requests_sent,
            "eta_display": eta_str,
            "pages_crawled": self.pages_crawled
        })

    def _probe_executed_handler(self, data: Dict[str, Any]):
        self.total_requests_sent += 1
        self.probes_completed += 1
        payload_desc = data.get("payload_obj", {}).get("description", "Security probe")
        _, eta_str = self._calculate_eta()
        
        self._emit("request_sent", {
            "method": data.get("method"),
            "url": data.get("url"),
            "parameter": data.get("parameter"),
            "status_code": data.get("status_code", "ERR"),
            "elapsed_ms": round(data.get("elapsed_ms", 0), 1),
            "probe_description": payload_desc,
            "total_requests": self.total_requests_sent,
            "probes_completed": self.probes_completed,
            "total_probes_estimated": self.total_probes_estimated,
            "eta_display": eta_str
        })

    async def run_scan(self) -> Dict[str, Any]:
        """Execute the full autonomous scan workflow."""
        start_time = time.time()

        self._emit("stage_change", {
            "stage": "CRAWLING",
            "message": f"Autonomous discovery initiated on {self.target_url}...",
            "eta_display": "Calculating..."
        })

        # 1. Autonomous Web Crawling (with strict loop & duplicate prevention)
        self.discovered_endpoints = await self.crawler.crawl()
        
        if self.is_stopped:
            return ScanRepository.get_scan(self.scan_id)

        for ep in self.discovered_endpoints:
            ScanRepository.add_endpoint(
                scan_id=self.scan_id,
                url=ep.url,
                method=ep.method,
                params=ep.params,
                headers=ep.headers,
                discovered_via=ep.discovered_via
            )

        self._emit("endpoints_discovered", {
            "count": len(self.discovered_endpoints),
            "endpoints": [ep.to_dict() for ep in self.discovered_endpoints],
            "eta_display": "Calculating..."
        })

        if self.is_stopped:
            return ScanRepository.get_scan(self.scan_id)

        # 2. Static Client-Side Analysis
        self._emit("stage_change", {
            "stage": "STATIC_ANALYSIS",
            "message": "Analyzing client-side HTML, JavaScript, and HTTP headers...",
            "eta_display": "Calculating..."
        })

        for ep in self.discovered_endpoints:
            if self.is_stopped:
                break
            # Header security audit
            header_findings = self.static_engine.analyze_headers(ep.headers, ep.url)
            for hf in header_findings:
                if self.is_stopped:
                    break
                verdict = self.reasoning_engine.synthesize_finding(
                    endpoint_url=hf["url"],
                    http_method=ep.method,
                    parameter_name=hf["parameter"],
                    ml_prediction={"category": "Normal", "confidence": 90.0, "is_anomalous": False},
                    static_evidence=hf
                )
                self._record_finding(verdict)

            # HTML & Script audit if page content was retrieved
            if ep.raw_html and not self.is_stopped:
                html_findings = self.static_engine.analyze_html_and_scripts(ep.raw_html, ep.url)
                for hf in html_findings:
                    if self.is_stopped:
                        break
                    verdict = self.reasoning_engine.synthesize_finding(
                        endpoint_url=hf["url"],
                        http_method=ep.method,
                        parameter_name=hf["parameter"],
                        ml_prediction={"category": "Normal", "confidence": 90.0, "is_anomalous": False},
                        static_evidence=hf
                    )
                    self._record_finding(verdict)

        if self.is_stopped:
            return ScanRepository.get_scan(self.scan_id)

        # 3. Compute Total Probes for Accurate ETA Tracking
        total_params_to_test = sum(len(ep.params) for ep in self.discovered_endpoints)
        probes_per_param = sum(len(p_list) for p_list in PROBES.values())
        self.total_probes_estimated = total_params_to_test * probes_per_param
        self.fuzz_start_time = time.time()
        self.probes_completed = 0

        # 4. Dynamic Analysis & Non-Destructive Differential Fuzzing + ML Classification
        self._emit("stage_change", {
            "stage": "DYNAMIC_FUZZING_AND_ML",
            "message": "Executing controlled differential security probes and ML scoring...",
            "total_probes": self.total_probes_estimated,
            "eta_display": "Calculating..."
        })

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in self.discovered_endpoints:
                if self.is_stopped:
                    break
                for param_info in ep.params:
                    if self.is_stopped:
                        break
                    p_name = param_info["name"]
                    _, eta_str = self._calculate_eta()
                    
                    self._emit("testing_parameter", {
                        "url": ep.url,
                        "method": ep.method,
                        "parameter": p_name,
                        "probes_completed": self.probes_completed,
                        "total_probes": self.total_probes_estimated,
                        "eta_display": eta_str
                    })

                    dynamic_results = await self.dynamic_engine.analyze_endpoint_parameter(ep, p_name, client)

                    for dyn_res in dynamic_results:
                        if self.is_stopped:
                            break
                        raw_req = dyn_res.get("raw_request", "")
                        
                        # 5. ML Request Classification
                        ml_pred = self.ml_predictor.predict_request(raw_req)
                        self._emit("ml_scored", {
                            "category": ml_pred.get("category"),
                            "confidence": ml_pred.get("confidence"),
                            "is_anomalous": ml_pred.get("is_anomalous"),
                            "url": ep.url,
                            "parameter": p_name
                        })

                        # 6. Local & Google Gemini Cyber-Reasoning Synthesis (CVSS v4.0 Standard)
                        verdict = self.reasoning_engine.synthesize_finding(
                            endpoint_url=ep.url,
                            http_method=ep.method,
                            parameter_name=p_name,
                            ml_prediction=ml_pred,
                            dynamic_evidence=dyn_res.get("dynamic_analysis")
                        )
                        self._record_finding(verdict)

        if self.is_stopped:
            return ScanRepository.get_scan(self.scan_id)

        # 7. Finalize Scan with Complete CVSS v4.0 Summary and IST Timestamps
        duration = time.time() - start_time
        summary = {
            "duration_sec": round(duration, 2),
            "endpoints_scanned": len(self.discovered_endpoints),
            "total_requests": self.total_requests_sent,
            "total_findings": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f.get("severity") == "CRITICAL"),
            "high_count": sum(1 for f in self.findings if f.get("severity") == "HIGH"),
            "medium_count": sum(1 for f in self.findings if f.get("severity") == "MEDIUM"),
            "low_count": sum(1 for f in self.findings if f.get("severity") == "LOW"),
            "none_count": sum(1 for f in self.findings if f.get("severity") == "NONE"),
            "confirmed_count": sum(1 for f in self.findings if f.get("status") == "Confirmed"),
            "completed_at": get_ist_iso()
        }

        ScanRepository.update_scan_status(self.scan_id, "COMPLETED", summary)
        self._emit("scan_completed", {
            "scan_id": self.scan_id,
            "summary": summary,
            "eta_display": "Completed"
        })

        return ScanRepository.get_scan(self.scan_id)
