"""
Cyber-Reasoning Engine with Google Gemini LLM Integration and CVSS v4.0 Severity Classification.
Multi-evidence synthesis layer correlating ML predictions, dynamic probe differentials,
static client-side findings, and HTTP behavioral telemetry into structured security verdicts.
"""

import os
import json
from typing import Dict, Any, List, Optional
from backend.cvss.cvss_v4 import compute_cvss_v4
from backend.utils.timezone import get_ist_iso

GEMINI_API_KEY_DEFAULT = "AQ.Ab8RN6IQy9cPqLtGBYAKXcY8_YGHIcUNfkR2FNEY3QXtyxJ0sw"


class GeminiReasoningClient:
    """Client for querying Google Gemini LLM to generate vulnerability analysis, exact location, and brief remediation."""
    _instance: Optional["GeminiReasoningClient"] = None

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", GEMINI_API_KEY_DEFAULT)
        self.client = None
        self.preferred_models = [
            "gemini-3.5-flash-lite",
            "gemini-3.6-flash",
            "gemini-3.1-pro-preview",
            "gemini-2.5-pro",
            "gemini-3.7-flash"
        ]
        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                # Log without exposing key
                print(f"[GeminiClient] Initialization note: {type(e).__name__}")

    @classmethod
    def get_instance(cls) -> "GeminiReasoningClient":
        if cls._instance is None:
            cls._instance = GeminiReasoningClient()
        return cls._instance

    def analyze_vulnerability(
        self,
        vuln_type: str,
        url: str,
        method: str,
        parameter: Optional[str],
        ml_prediction: Dict[str, Any],
        dynamic_evidence: Optional[Dict[str, Any]] = None,
        static_evidence: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, str]]:
        """Query Google Gemini to generate brief info, exact location, and brief remediation."""
        if not self.client:
            return None

        prompt = f"""You are an expert AI cyber-reasoning engine analyzing an authorized web security scan finding.

Context:
- Vulnerability Type: {vuln_type}
- Target URL: {url}
- HTTP Method: {method}
- Vulnerable Parameter / Field: {parameter or 'N/A (Header or Document body)'}
- ML Classifier Prediction: {ml_prediction.get('category')} ({ml_prediction.get('confidence')}%)
- Dynamic Behavioral Evidence: {json.dumps(dynamic_evidence or {}, default=str)}
- Client-Side Static Evidence: {json.dumps(static_evidence or {}, default=str)}

Respond ONLY in valid JSON with these exact 3 keys:
{{
  "brief_info": "A 2-3 sentence explanation of the vulnerability found and its operational risk.",
  "exact_location": "A precise 1-line description of where exactly it was found (URL, method, parameter, or header).",
  "brief_remediation": "A concise 2-3 bullet point or short paragraph instruction on how to remediate the vulnerability."
}}"""

        for model_name in self.preferred_models:
            try:
                resp = self.client.models.generate_content(
                    model=model_name,
                    contents=prompt
                )
                text = resp.text.strip()
                # Clean markdown backticks if wrapped
                if text.startswith("```json"):
                    text = text[7:]
                if text.startswith("```"):
                    text = text[3:]
                if text.endswith("```"):
                    text = text[:-3]
                text = text.strip()
                data = json.loads(text)
                if "brief_info" in data and "exact_location" in data and "brief_remediation" in data:
                    data["model_used"] = model_name
                    return data
            except Exception:
                # Try next model in fallback list
                continue

        return None


class CyberReasoningEngine:
    """
    Local & Cloud Cyber-Reasoning Engine.
    Correlates multiple independent telemetry streams:
    - ML Statistical Classifier Output (trained on vyykaaa/dataset-v2)
    - Dynamic Fuzzing Probe & Differential Response Evidence
    - Static Client-Side Code & Header Analysis
    - Google Gemini LLM Cyber-Reasoning Layer
    - CVSS v4.0 Severity Classification Standard
    """

    def __init__(self, gemini_api_key: Optional[str] = None):
        self.gemini_client = GeminiReasoningClient.get_instance()
        if gemini_api_key:
            self.gemini_client = GeminiReasoningClient(api_key=gemini_api_key)

    def synthesize_finding(
        self,
        endpoint_url: str,
        http_method: str,
        parameter_name: Optional[str],
        ml_prediction: Dict[str, Any],
        dynamic_evidence: Optional[Dict[str, Any]] = None,
        static_evidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Synthesize multi-modal evidence into a final verdict with reasoning, confidence, and CVSS v4.0 severity.
        """
        dynamic_evidence = dynamic_evidence or {}
        static_evidence = static_evidence or {}
        
        ml_cat = ml_prediction.get("category", "Normal")
        ml_conf = float(ml_prediction.get("confidence", 50.0))
        ml_anom = ml_prediction.get("is_anomalous", False)

        has_dynamic_proof = bool(
            dynamic_evidence.get("sql_error_matched") or
            dynamic_evidence.get("canary_reflected") or
            dynamic_evidence.get("traversal_match") or
            dynamic_evidence.get("calculated_result_reflected") or
            dynamic_evidence.get("command_echo_reflected") or
            dynamic_evidence.get("injected_header_found") or
            dynamic_evidence.get("redirect_location")
        )

        has_dynamic_anomaly = bool(
            dynamic_evidence.get("differential_anomaly") or
            (dynamic_evidence.get("status_code") == 500 and dynamic_evidence.get("baseline_status") == 200)
        )

        # 1. Determine Final Classification Category
        if has_dynamic_proof:
            if dynamic_evidence.get("sql_error_matched"):
                final_cat = "SQL_Injection"
            elif dynamic_evidence.get("canary_reflected"):
                final_cat = "Cross_Site_Scripting"
            elif dynamic_evidence.get("traversal_match"):
                final_cat = "Directory_Traversal"
            elif dynamic_evidence.get("calculated_result_reflected"):
                final_cat = "Server_Side_Template_Injection"
            elif dynamic_evidence.get("command_echo_reflected"):
                final_cat = "Command_Injection"
            elif dynamic_evidence.get("injected_header_found"):
                final_cat = "CRLF_Injection"
            elif dynamic_evidence.get("redirect_location"):
                final_cat = "Open_Redirect"
            else:
                final_cat = ml_cat if ml_anom else "Suspicious_Behavior"
        elif static_evidence:
            final_cat = static_evidence.get("vuln_type", "Static_Finding")
        elif ml_anom:
            final_cat = ml_cat
        else:
            final_cat = "Normal"

        # 2. Compute Multi-Factor Calibrated Confidence & Status
        uncertainty_warning = ""
        if has_dynamic_proof:
            if ml_anom and (ml_cat == final_cat or ml_cat in final_cat):
                confidence = min(99.4, max(95.0, (ml_conf * 0.4) + 60.0))
            else:
                confidence = 94.0
            status = "Confirmed"
        elif static_evidence:
            confidence = static_evidence.get("confidence", 85.0)
            status = static_evidence.get("status", "Confirmed")
        elif has_dynamic_anomaly and ml_anom:
            confidence = round((ml_conf * 0.5) + 38.0, 1)
            status = "Potential"
            uncertainty_warning = "The target backend returned an HTTP 500 internal error upon receiving malicious probe characters, but did not directly echo canary output or database error details. This indicates unhandled input exceptions with potential exploitability."
        elif ml_anom:
            confidence = round(min(75.0, ml_conf * 0.75), 1)
            status = "Requires Verification"
            uncertainty_warning = "The ML classifier flagged this request structure as anomalous matching known attack signatures; however, the target server did not exhibit active differential reflection. Manual or authenticated verification is recommended to rule out false positives."
        else:
            confidence = 90.0
            status = "Normal"

        # 3. CVSS v4.0 Calculation & Severity Classification
        cvss_v4_info = compute_cvss_v4(final_cat, status, dynamic_evidence or static_evidence)
        cvss_score = cvss_v4_info["score"]
        cvss_vector = cvss_v4_info["vector"]
        severity = cvss_v4_info["severity"]

        # 4. Query Google Gemini LLM for Brief Info, Exact Location, and Brief Remediation
        gemini_result = self.gemini_client.analyze_vulnerability(
            vuln_type=final_cat,
            url=endpoint_url,
            method=http_method,
            parameter=parameter_name,
            ml_prediction=ml_prediction,
            dynamic_evidence=dynamic_evidence,
            static_evidence=static_evidence
        )

        # 5. Formulate Cyber-Reasoning Narrative
        reasoning_lines = []
        if gemini_result:
            reasoning_lines.append(f"🤖 **Google Gemini Cyber-Reasoning ({gemini_result.get('model_used', 'Gemini')}):**")
            reasoning_lines.append(f"• **Vulnerability Overview:** {gemini_result.get('brief_info')}")
            reasoning_lines.append(f"• **Exact Location:** {gemini_result.get('exact_location')}")
            reasoning_lines.append(f"• **Remediation Summary:** {gemini_result.get('brief_remediation')}")
            reasoning_lines.append("\n🔍 **Correlated Evidence & Telemetry:**")
        else:
            reasoning_lines.append(f"**Target Surface:** Endpoint `{http_method} {endpoint_url}` via parameter `{parameter_name or 'N/A'}`.")
        
        reasoning_lines.append(f"- **CVSS v4.0 Evaluation:** Score **{cvss_score}** ({severity}) | Vector: `{cvss_vector}`")
        if ml_anom:
            reasoning_lines.append(f"- **ML Dataset Classifier:** Statistical model identified `{ml_cat}` signature with **{ml_conf:.1f}%** confidence based on request syntax.")
            
        if has_dynamic_proof:
            reasoning_lines.append("- **Dynamic Fuzzing Differential:** Non-destructive probe confirmed vulnerability:")
            if dynamic_evidence.get("sql_error_matched"):
                reasoning_lines.append(f"  - Database Error: `{dynamic_evidence.get('detected_db')}` syntax exception: `\"{dynamic_evidence.get('sql_error_matched')}\"`.")
            if dynamic_evidence.get("canary_reflected"):
                reasoning_lines.append("  - Canary Reflection: Unsanitized probe payload reflected intact into response body.")
            if dynamic_evidence.get("traversal_match"):
                reasoning_lines.append(f"  - Traversal Leakage: Detected system file contents matching signature `{dynamic_evidence.get('traversal_match')}`.")
            if dynamic_evidence.get("calculated_result_reflected"):
                reasoning_lines.append(f"  - Template Execution: Evaluated arithmetic expression yielding `{dynamic_evidence.get('calculated_result_reflected')}`.")
            if dynamic_evidence.get("command_echo_reflected"):
                reasoning_lines.append("  - Command Output: Echo probe output was returned directly from host shell.")
            if dynamic_evidence.get("injected_header_found"):
                reasoning_lines.append(f"  - Header Injection: CRLF probe injected header `{dynamic_evidence.get('injected_header_found')}`.")
        elif static_evidence:
            reasoning_lines.append(f"- **Static Source Analysis:** Discovered `{static_evidence.get('title')}` in client-side code.")
        elif has_dynamic_anomaly:
            reasoning_lines.append("- **Dynamic Behavior Differential:** Probe triggered unexpected HTTP 500 error compared to baseline HTTP 200.")

        reasoning_lines.append(f"\n**Verdict:** Status **{status}** | Calibrated Confidence: **{confidence:.1f}%** | CVSS v4.0: **{cvss_score}** ({severity}).")

        # Remediation resolution
        if gemini_result and gemini_result.get("brief_remediation"):
            remediation = gemini_result.get("brief_remediation")
        else:
            remediation_map = {
                "SQL_Injection": "Replace dynamic string concatenation with parameterized prepared statements. Use ORM parameter binding or parameterized DB-API calls.",
                "Cross_Site_Scripting": "Implement context-aware HTML entity encoding on all user-supplied outputs. Set Content-Security-Policy headers with strict script restrictions.",
                "Directory_Traversal": "Sanitize file path inputs using os.path.basename. Validate resolved absolute paths against an authorized base directory whitelist.",
                "Server_Side_Template_Injection": "Pass user values into template context dictionaries rather than formatting them into template source strings.",
                "Command_Injection": "Avoid invoking system shells. Use subprocess APIs with explicit argument lists (shell=False) and strict input validation.",
                "CRLF_Injection": "Sanitize and strip CR (\\r, %0d) and LF (\\n, %0a) characters before setting custom HTTP headers or cookie values.",
                "Open_Redirect": "Enforce strict whitelisting of authorized redirect targets or use internal relative paths only."
            }
            remediation = static_evidence.get("remediation") or remediation_map.get(final_cat, "Enforce strict input validation, principle of least privilege, and robust server-side error handling.")

        exact_location_str = gemini_result.get("exact_location") if gemini_result else f"{http_method} {endpoint_url} (param: {parameter_name or 'N/A'})"
        brief_info_str = gemini_result.get("brief_info") if gemini_result else f"Detected potential {final_cat.replace('_', ' ')} vulnerability with {confidence:.1f}% confidence."

        return {
            "vuln_type": final_cat,
            "category": final_cat.replace("_", " "),
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_v4": cvss_v4_info,
            "confidence": confidence,
            "status": status,
            "url": endpoint_url,
            "parameter": parameter_name,
            "http_method": http_method,
            "brief_info": brief_info_str,
            "exact_location": exact_location_str,
            "brief_remediation": remediation,
            "gemini_analysis": gemini_result,
            "ml_prediction": ml_prediction,
            "dynamic_analysis": dynamic_evidence,
            "static_analysis": static_evidence,
            "llm_reasoning": "\n".join(reasoning_lines),
            "remediation": remediation,
            "uncertainty_warning": uncertainty_warning,
            "detected_at": get_ist_iso()
        }
