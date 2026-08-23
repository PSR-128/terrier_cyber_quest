import pytest
from backend.fuzzing.payload_generator import get_probes_for_category, get_all_categories, CANARY_ID

def test_payload_generator_categories():
    categories = get_all_categories()
    assert "SQL_Injection" in categories
    assert "Cross_Site_Scripting" in categories
    assert "Directory_Traversal" in categories
    assert "Command_Injection" in categories
    assert "Server_Side_Template_Injection" in categories

def test_probes_structure():
    sqli_probes = get_probes_for_category("SQL_Injection")
    assert len(sqli_probes) > 0
    assert any("payload" in p for p in sqli_probes)
    
    xss_probes = get_probes_for_category("Cross_Site_Scripting")
    assert any(CANARY_ID in p["payload"] for p in xss_probes)
