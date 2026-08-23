"""
Tests for vulnerability deduplication logic.
Verifies:
1. Fingerprint computation correctly identifies same vs different vulnerabilities.
2. Dynamic engine break-on-first-confirm produces at most 1 finding per (url, param, category).
3. Missing security headers across multiple URLs consolidate into 1 finding per header.
4. Same vuln type on different parameters produces separate findings.
5. Different vuln types on the same parameter produce separate findings.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from backend.scanner.orchestrator import ScanOrchestrator


class TestFingerprintComputation:
    """Test _compute_fingerprint produces correct identity semantics."""

    def _make_orchestrator(self):
        with patch.object(ScanOrchestrator, '__init__', lambda self, *a, **kw: None):
            orch = ScanOrchestrator.__new__(ScanOrchestrator)
            orch.scan_id = "test-scan"
            orch.findings = []
            orch._seen_fingerprints = {}
            orch.on_event = None
            return orch

    def test_same_vuln_same_fingerprint(self):
        """Same (url_path, vuln_type, param) should produce the same fingerprint."""
        orch = self._make_orchestrator()
        fp1 = orch._compute_fingerprint("SQL_Injection", "http://localhost:3000/api/search?q=test", "q")
        fp2 = orch._compute_fingerprint("SQL_Injection", "http://localhost:3000/api/search?q=other", "q")
        assert fp1 == fp2, "Same path+param+type should produce identical fingerprint regardless of query values"

    def test_different_params_different_fingerprint(self):
        """Same vuln type on different parameters should produce different fingerprints."""
        orch = self._make_orchestrator()
        fp1 = orch._compute_fingerprint("SQL_Injection", "http://localhost:3000/api/search", "id")
        fp2 = orch._compute_fingerprint("SQL_Injection", "http://localhost:3000/api/search", "name")
        assert fp1 != fp2, "Different parameters should produce distinct fingerprints"

    def test_different_vuln_types_different_fingerprint(self):
        """Different vuln types on the same URL+param should produce different fingerprints."""
        orch = self._make_orchestrator()
        fp1 = orch._compute_fingerprint("SQL_Injection", "http://localhost:3000/api/search", "q")
        fp2 = orch._compute_fingerprint("Cross_Site_Scripting", "http://localhost:3000/api/search", "q")
        assert fp1 != fp2, "Different vulnerability types must produce distinct fingerprints"

    def test_missing_header_consolidates_across_paths(self):
        """Missing_Security_Header findings should deduplicate across different URL paths."""
        orch = self._make_orchestrator()
        fp1 = orch._compute_fingerprint("Missing_Security_Header", "http://localhost:3000/page1", "Content-Security-Policy")
        fp2 = orch._compute_fingerprint("Missing_Security_Header", "http://localhost:3000/page2", "Content-Security-Policy")
        assert fp1 == fp2, "Server-wide config issues should use origin-only normalization"

    def test_different_headers_separate_fingerprints(self):
        """Different missing headers on the same server should be separate findings."""
        orch = self._make_orchestrator()
        fp1 = orch._compute_fingerprint("Missing_Security_Header", "http://localhost:3000/page1", "Content-Security-Policy")
        fp2 = orch._compute_fingerprint("Missing_Security_Header", "http://localhost:3000/page1", "X-Frame-Options")
        assert fp1 != fp2, "Different header parameters must produce distinct fingerprints"

    def test_cors_consolidates_across_paths(self):
        """Insecure_CORS_Policy should also consolidate across paths."""
        orch = self._make_orchestrator()
        fp1 = orch._compute_fingerprint("Insecure_CORS_Policy", "http://localhost:3000/api/v1", "Access-Control-Allow-Origin")
        fp2 = orch._compute_fingerprint("Insecure_CORS_Policy", "http://localhost:3000/api/v2", "Access-Control-Allow-Origin")
        assert fp1 == fp2, "CORS policy is server-wide and should consolidate"


class TestRecordFinding:
    """Test _record_finding deduplication gate."""

    def _make_orchestrator(self):
        with patch.object(ScanOrchestrator, '__init__', lambda self, *a, **kw: None):
            orch = ScanOrchestrator.__new__(ScanOrchestrator)
            orch.scan_id = "test-scan"
            orch.findings = []
            orch._seen_fingerprints = {}
            orch.on_event = None
            return orch

    @patch('backend.scanner.orchestrator.ScanRepository')
    def test_first_finding_recorded(self, mock_repo):
        """First finding for a fingerprint should be stored and emitted."""
        orch = self._make_orchestrator()
        orch._emit = MagicMock()

        verdict = {
            "vuln_type": "SQL_Injection",
            "url": "http://localhost:3000/api/search",
            "parameter": "q",
            "confidence": 94.5,
            "severity": "HIGH"
        }

        result = orch._record_finding(verdict)
        assert result is True
        assert len(orch.findings) == 1
        assert orch._emit.call_count == 1
        mock_repo.add_finding.assert_called_once()

    @patch('backend.scanner.orchestrator.ScanRepository')
    def test_duplicate_finding_suppressed(self, mock_repo):
        """Second finding with same fingerprint and lower confidence should be suppressed."""
        orch = self._make_orchestrator()
        orch._emit = MagicMock()

        verdict1 = {
            "vuln_type": "SQL_Injection",
            "url": "http://localhost:3000/api/search",
            "parameter": "q",
            "confidence": 94.5,
            "severity": "HIGH"
        }
        verdict2 = {
            "vuln_type": "SQL_Injection",
            "url": "http://localhost:3000/api/search",
            "parameter": "q",
            "confidence": 80.0,
            "severity": "HIGH"
        }

        orch._record_finding(verdict1)
        result = orch._record_finding(verdict2)

        assert result is False
        assert len(orch.findings) == 1, "Duplicate should not add a second finding"
        assert orch.findings[0]["confidence"] == 94.5, "Original higher-confidence finding should be kept"

    @patch('backend.scanner.orchestrator.ScanRepository')
    def test_higher_confidence_replaces(self, mock_repo):
        """Second finding with higher confidence should replace the existing one."""
        orch = self._make_orchestrator()
        orch._emit = MagicMock()

        verdict1 = {
            "vuln_type": "SQL_Injection",
            "url": "http://localhost:3000/api/search",
            "parameter": "q",
            "confidence": 80.0,
            "severity": "HIGH"
        }
        verdict2 = {
            "vuln_type": "SQL_Injection",
            "url": "http://localhost:3000/api/search",
            "parameter": "q",
            "confidence": 96.0,
            "severity": "HIGH"
        }

        orch._record_finding(verdict1)
        orch._record_finding(verdict2)

        assert len(orch.findings) == 1, "Should still be only 1 finding"
        assert orch.findings[0]["confidence"] == 96.0, "Higher-confidence finding should replace"

    @patch('backend.scanner.orchestrator.ScanRepository')
    def test_different_params_both_recorded(self, mock_repo):
        """Same vuln type on different params should both be recorded."""
        orch = self._make_orchestrator()
        orch._emit = MagicMock()

        verdict1 = {
            "vuln_type": "SQL_Injection",
            "url": "http://localhost:3000/api/search",
            "parameter": "id",
            "confidence": 94.5,
            "severity": "HIGH"
        }
        verdict2 = {
            "vuln_type": "SQL_Injection",
            "url": "http://localhost:3000/api/search",
            "parameter": "name",
            "confidence": 94.5,
            "severity": "HIGH"
        }

        orch._record_finding(verdict1)
        orch._record_finding(verdict2)

        assert len(orch.findings) == 2, "Different parameters = different vulnerabilities"

    @patch('backend.scanner.orchestrator.ScanRepository')
    def test_header_dedup_across_urls(self, mock_repo):
        """Missing_Security_Header for same header on different URLs = 1 finding."""
        orch = self._make_orchestrator()
        orch._emit = MagicMock()

        verdict1 = {
            "vuln_type": "Missing_Security_Header",
            "url": "http://localhost:3000/page1",
            "parameter": "Content-Security-Policy",
            "confidence": 95.0,
            "severity": "MEDIUM"
        }
        verdict2 = {
            "vuln_type": "Missing_Security_Header",
            "url": "http://localhost:3000/page2",
            "parameter": "Content-Security-Policy",
            "confidence": 95.0,
            "severity": "MEDIUM"
        }

        orch._record_finding(verdict1)
        result = orch._record_finding(verdict2)

        assert result is False
        assert len(orch.findings) == 1, "Same missing header across URLs = 1 finding"
