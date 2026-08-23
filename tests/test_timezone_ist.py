import pytest
from backend.utils.timezone import get_ist_now, get_ist_iso, format_ist_display, to_ist

def test_ist_timezone_offset():
    now_ist = get_ist_now()
    offset_seconds = now_ist.utcoffset().total_seconds()
    # IST is UTC+05:30 -> 5.5 * 3600 = 19800 seconds
    assert offset_seconds == 19800

def test_ist_iso_format():
    iso_str = get_ist_iso()
    assert "+05:30" in iso_str

def test_format_ist_display():
    formatted = format_ist_display("2026-08-20T12:00:00Z")
    assert "IST" in formatted
    # 12:00 UTC is 17:30 IST (05:30 PM)
    assert "05:30:00 PM" in formatted
