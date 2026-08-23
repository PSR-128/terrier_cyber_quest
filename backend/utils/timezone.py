"""
Timezone Utility Module.
Enforces Indian Standard Time (IST, UTC+05:30) across the entire application:
logging, database records, reports, and UI display timestamps.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Union

# IST is UTC+05:30
IST_OFFSET = timedelta(hours=5, minutes=30)
IST_TZ = timezone(IST_OFFSET, name="IST")


def get_ist_now() -> datetime:
    """Return the current datetime in Indian Standard Time (IST, UTC+05:30)."""
    return datetime.now(timezone.utc).astimezone(IST_TZ)


def get_ist_iso() -> str:
    """Return the current IST datetime as an ISO-8601 string with explicit offset."""
    return get_ist_now().isoformat()


def to_ist(dt_or_str: Union[datetime, str, None]) -> datetime:
    """Convert a UTC or naive datetime/ISO string to IST datetime."""
    if dt_or_str is None:
        return get_ist_now()

    if isinstance(dt_or_str, str):
        # Clean string format
        clean_str = dt_or_str.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(clean_str)
        except Exception:
            return get_ist_now()
    else:
        dt = dt_or_str

    if dt.tzinfo is None:
        # Assume UTC if naive
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(IST_TZ)


def format_ist_display(dt_or_str: Union[datetime, str, None], include_seconds: bool = True) -> str:
    """
    Format a datetime/ISO string as user-friendly IST string:
    e.g. '20 Aug 2026, 11:05:30 PM IST'
    """
    ist_dt = to_ist(dt_or_str)
    if include_seconds:
        return ist_dt.strftime("%d %b %Y, %I:%M:%S %p IST")
    return ist_dt.strftime("%d %b %Y, %I:%M %p IST")


def format_ist_time_only(dt_or_str: Union[datetime, str, None]) -> str:
    """
    Format time portion in IST: e.g. '11:05:30 PM IST'
    """
    ist_dt = to_ist(dt_or_str)
    return ist_dt.strftime("%I:%M:%S %p IST")
