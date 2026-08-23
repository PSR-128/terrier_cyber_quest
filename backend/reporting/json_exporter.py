"""
JSON Export and Telemetry Serializer.
"""

import json
from typing import Dict, Any


class JSONExporter:
    @staticmethod
    def export_scan(scan_data: Dict[str, Any], pretty: bool = True) -> str:
        """Serialize complete scan telemetry and results to JSON."""
        indent = 2 if pretty else None
        return json.dumps(scan_data, indent=indent, default=str)
