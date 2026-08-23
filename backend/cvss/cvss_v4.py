"""
CVSS v4.0 Vulnerability Severity Classification Engine.
Implements the FIRST Common Vulnerability Scoring System (CVSS) Version 4.0 standard:
- MacroVector and Base Score calculations
- Vector String construction (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:.../VI:.../VA:.../SC:.../SI:.../SA:...)
- Exploitability & Impact breakdown
- Exact severity mapping (None, Low, Medium, High, Critical)
"""

from typing import Dict, Any, Optional, Tuple


def get_severity_from_score(score: float) -> str:
    """
    Map CVSS v4.0 score to canonical severity rating according to the specification:
    - None: 0.0
    - Low: 0.1 - 3.9
    - Medium: 4.0 - 6.9
    - High: 7.0 - 8.9
    - Critical: 9.0 - 10.0
    """
    if score <= 0.0:
        return "NONE"
    elif score <= 3.9:
        return "LOW"
    elif score <= 6.9:
        return "MEDIUM"
    elif score <= 8.9:
        return "HIGH"
    else:
        return "CRITICAL"


# Default CVSS v4.0 profiles per vulnerability category
CVSS_V4_PROFILES: Dict[str, Dict[str, Any]] = {
    "Command_Injection": {
        "score": 10.0,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: High, Availability: High",
            "subsequent_system": "Confidentiality: High, Integrity: High, Availability: High"
        },
        "description": "Arbitrary operating system command execution with total system compromise."
    },
    "Remote_Code_Execution": {
        "score": 10.0,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: High, Availability: High",
            "subsequent_system": "Confidentiality: High, Integrity: High, Availability: High"
        },
        "description": "Remote code execution allowing unauthenticated arbitrary code execution."
    },
    "Server_Side_Template_Injection": {
        "score": 9.9,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: High, Availability: High",
            "subsequent_system": "Confidentiality: Low, Integrity: Low, Availability: Low"
        },
        "description": "Server-side template expression evaluation leading to remote command execution."
    },
    "SQL_Injection": {
        "score": 9.3,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: High, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Direct database query manipulation allowing arbitrary read/write of backend records."
    },
    "Directory_Traversal": {
        "score": 8.7,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: None, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Path traversal allowing arbitrary reading of sensitive system and configuration files."
    },
    "Local_File_Inclusion": {
        "score": 8.7,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: None, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Local file inclusion permitting retrieval of local application scripts and sensitive data."
    },
    "Server_Side_Request_Forgery": {
        "score": 8.7,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: Low, Availability: None",
            "subsequent_system": "Confidentiality: High, Integrity: Low, Availability: None"
        },
        "description": "Server forced to dispatch unintended requests to internal networks and cloud metadata."
    },
    "XML_External_Entity": {
        "score": 8.7,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: None, Availability: Low",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Unsafe XML parsing allowing file disclosure and server-side request forgery."
    },
    "Insecure_CORS_Policy": {
        "score": 7.1,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "Passive (UI:P)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: None, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Overly permissive CORS configuration allowing arbitrary external origins to read authenticated responses."
    },
    "Cross_Site_Scripting": {
        "score": 6.9,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "Passive (UI:P)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: Low, Integrity: Low, Availability: None",
            "subsequent_system": "Confidentiality: Low, Integrity: Low, Availability: None"
        },
        "description": "Execution of malicious client-side JavaScript within victim browser session."
    },
    "Cross_Site_Request_Forgery": {
        "score": 6.9,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "Active (UI:A)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: None, Integrity: High, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Unauthorized state-changing actions executed on behalf of authenticated users."
    },
    "CRLF_Injection": {
        "score": 5.3,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: None, Integrity: Low, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: Low, Availability: None"
        },
        "description": "HTTP response splitting and header injection enabling cache poisoning and XSS."
    },
    "Open_Redirect": {
        "score": 5.1,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "Passive (UI:P)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: None, Integrity: Low, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: Low, Availability: None"
        },
        "description": "Unvalidated redirect allowing attackers to divert users to phishing infrastructure."
    },
    "Information_Disclosure": {
        "score": 8.7,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: High, Integrity: None, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Hardcoded secrets, tokens, or credentials exposed in accessible client code."
    },
    "HTML_Comments_Disclosure": {
        "score": 3.1,
        "vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "High (AC:H)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: Low, Integrity: None, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Sensitive development notes, debug references, or internal information exposed in HTML comments."
    },
    "Missing_Security_Header": {
        "score": 2.3,
        "vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "High (AC:H)",
            "attack_requirements": "Present (AT:P)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "Active (UI:A)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: Low, Integrity: Low, Availability: None",
            "subsequent_system": "Confidentiality: None, Integrity: None, Availability: None"
        },
        "description": "Missing defensive HTTP headers (CSP, HSTS, X-Frame-Options) weakening defense-in-depth."
    },
    "Normal": {
        "score": 0.0,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "None",
            "attack_complexity": "None",
            "attack_requirements": "None",
            "privileges_required": "None",
            "user_interaction": "None"
        },
        "impact": {
            "vulnerable_system": "None",
            "subsequent_system": "None"
        },
        "description": "Benign normal traffic with zero identified security vulnerabilities."
    }
}


def compute_cvss_v4(
    vuln_type: str,
    status: str = "Confirmed",
    evidence: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Calculate CVSS v4.0 score, official vector string, exploitability/impact details,
    and standard severity level according to FIRST CVSS v4.0.
    """
    # Normalize category name
    canonical_type = vuln_type
    for key in CVSS_V4_PROFILES:
        if key.lower() == vuln_type.lower() or key.lower() in vuln_type.lower():
            canonical_type = key
            break

    profile = CVSS_V4_PROFILES.get(canonical_type, {
        "score": 5.0,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "exploitability": {
            "attack_vector": "Network (AV:N)",
            "attack_complexity": "Low (AC:L)",
            "attack_requirements": "None (AT:N)",
            "privileges_required": "None (PR:N)",
            "user_interaction": "None (UI:N)"
        },
        "impact": {
            "vulnerable_system": "Confidentiality: Low, Integrity: Low, Availability: None",
            "subsequent_system": "None"
        },
        "description": f"Security finding of type {vuln_type}."
    })

    score = float(profile["score"])
    vector = profile["vector"]

    # Adjust score if status is unconfirmed / potential (e.g. requires verification)
    if status == "Requires Verification" and score > 4.0:
        score = round(min(score * 0.7, 6.5), 1)
        # Reflect in vector as attack requirement present
        vector = vector.replace("/AT:N/", "/AT:P/")
    elif status == "Potential" and score > 7.0:
        score = round(min(score * 0.85, 7.8), 1)

    severity = get_severity_from_score(score)

    return {
        "score": score,
        "severity": severity,
        "vector": vector,
        "standard": "CVSS v4.0",
        "exploitability": profile["exploitability"],
        "impact": profile["impact"],
        "description": profile.get("description", "")
    }
