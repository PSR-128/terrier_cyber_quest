import pytest
import asyncio
from backend.scanner.orchestrator import ScanOrchestrator
from backend.database.db import ScanRepository

@pytest.mark.asyncio
async def test_stop_scan_orchestrator():
    orchestrator = ScanOrchestrator(
        target_url="http://127.0.0.1:5000",
        scope_config={"max_depth": 3, "max_pages": 50}
    )

    # Immediately stop scan
    orchestrator.stop()
    assert orchestrator.is_stopped is True
    
    # Verify DB update
    scan = ScanRepository.get_scan(orchestrator.scan_id)
    assert scan is not None
    assert scan["status"] == "STOPPED"
