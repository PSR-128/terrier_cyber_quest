"""
OWASP Juice Shop Vulnerability Dataset Generator.
Extracts structured vulnerability records from locally running OWASP Juice Shop instance (http://localhost:3000).
Harvests challenge metadata, vulnerable code snippets, verified secure patches, CWE classifications,
endpoints, parameters, technical evidence, and validation tests.
"""

import os
import re
import json
import csv
import logging
from typing import Dict, Any, List, Optional, Tuple
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("juiceshop_generator")

BASE_URL = os.environ.get("JUICESHOP_URL", "http://localhost:3000")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Canonical Category to CWE & Vulnerability Type Mapping
CATEGORY_CWE_MAPPING = {
    "Injection": {
        "default": ("SQL_Injection", "CWE-89"),
        "nosql": ("NoSQL_Injection", "CWE-943"),
        "prompt": ("Prompt_Injection", "CWE-77"),
        "xee": ("XML_External_Entity", "CWE-611"),
        "ssti": ("Server_Side_Template_Injection", "CWE-1336")
    },
    "XSS": {
        "default": ("Cross_Site_Scripting", "CWE-79")
    },
    "Broken Access Control": {
        "default": ("Broken_Access_Control", "CWE-285")
    },
    "Sensitive Data Exposure": {
        "default": ("Sensitive_Data_Exposure", "CWE-200")
    },
    "Broken Authentication": {
        "default": ("Broken_Authentication", "CWE-287")
    },
    "Improper Input Validation": {
        "default": ("Improper_Input_Validation", "CWE-20")
    },
    "Observability Failures": {
        "default": ("Observability_Failures", "CWE-778")
    },
    "Unvalidated Redirects": {
        "default": ("Unvalidated_Redirects", "CWE-601")
    },
    "XXE": {
        "default": ("XML_External_Entity", "CWE-611")
    },
    "Insecure Deserialization": {
        "default": ("Insecure_Deserialization", "CWE-502")
    },
    "Cryptographic Issues": {
        "default": ("Cryptographic_Issues", "CWE-327")
    },
    "Security Misconfiguration": {
        "default": ("Security_Misconfiguration", "CWE-16")
    },
    "Broken Anti Automation": {
        "default": ("Broken_Anti_Automation", "CWE-799")
    },
    "Vulnerable Components": {
        "default": ("Vulnerable_Components", "CWE-1395")
    },
    "Security through Obscurity": {
        "default": ("Security_through_Obscurity", "CWE-656")
    },
    "Miscellaneous": {
        "default": ("Miscellaneous_Security_Flaw", "CWE-699")
    }
}

# Known Endpoint & Parameter mappings from Juice Shop routes
KNOWN_ROUTES_MAP = {
    "loginAdminChallenge": ("/rest/user/login", "email", "POST"),
    "loginBenderChallenge": ("/rest/user/login", "email", "POST"),
    "loginJimChallenge": ("/rest/user/login", "email", "POST"),
    "unionSqlInjectionChallenge": ("/rest/products/search", "q", "GET"),
    "dbSchemaChallenge": ("/rest/products/search", "q", "GET"),
    "restfulXssChallenge": ("/api/Products", "description", "POST"),
    "localXssChallenge": ("/#/search", "q", "GET"),
    "xssBonusChallenge": ("/#/track-result", "id", "GET"),
    "persistedXssUserChallenge": ("/rest/user/change-password", "current", "POST"),
    "reflectedXssChallenge": ("/#/track-result", "id", "GET"),
    "usernameXssChallenge": ("/profile", "username", "POST"),
    "directoryListingChallenge": ("/ftp", "not_available", "GET"),
    "forgottenDevBackupChallenge": ("/ftp/package.json.bak", "not_available", "GET"),
    "forgottenBackupChallenge": ("/ftp/coupons_2013.md.bak", "not_available", "GET"),
    "easterEggLevelTwoChallenge": ("/the/devs/are/so/funny/they/forgot/about/this/easter/egg", "not_available", "GET"),
    "misplacedSignatureFileChallenge": ("/ftp/suspicious_orders.doc", "not_available", "GET"),
    "nullByteChallenge": ("/ftp/package.json.bak%2500.md", "not_available", "GET"),
    "passwordHashLeakChallenge": ("/rest/user/authentication-details", "not_available", "GET"),
    "adminSectionChallenge": ("/#/administration", "not_available", "GET"),
    "registerAdminChallenge": ("/api/Users", "role", "POST"),
    "changeProductChallenge": ("/api/Products/1", "description", "PUT"),
    "forgedReviewChallenge": ("/rest/products/reviews", "message", "PATCH"),
    "noSqlReviewsChallenge": ("/rest/products/reviews", "id", "PATCH"),
    "noSqlOrdersChallenge": ("/rest/track-order/:id", "id", "GET"),
    "redirectChallenge": ("/redirect", "to", "GET"),
    "redirectCryptoCurrencyChallenge": ("/redirect", "to", "GET"),
    "weakPasswordChallenge": ("/rest/user/login", "password", "POST"),
    "resetPasswordBenderChallenge": ("/rest/user/reset-password", "answer", "POST"),
    "resetPasswordBjoernChallenge": ("/rest/user/reset-password", "answer", "POST"),
    "resetPasswordJimChallenge": ("/rest/user/reset-password", "answer", "POST"),
    "resetPasswordMortyChallenge": ("/rest/user/reset-password", "answer", "POST"),
    "resetPasswordUvoginChallenge": ("/rest/user/reset-password", "answer", "POST"),
    "resetPasswordBjoernOwaspChallenge": ("/rest/user/reset-password", "answer", "POST"),
    "accessLogDisclosureChallenge": ("/support/logs/access.log", "not_available", "GET"),
    "exposedMetricsChallenge": ("/metrics", "not_available", "GET"),
    "dlpPasswordSprayingChallenge": ("/rest/user/login", "password", "POST"),
    "nftUnlockChallenge": ("/rest/web3/wallet", "not_available", "GET"),
    "nftMintChallenge": ("/rest/web3/mint", "not_available", "POST"),
    "web3WalletChallenge": ("/rest/web3/wallet", "amount", "POST"),
    "web3SandboxChallenge": ("/#/web3-sandbox", "not_available", "GET"),
    "scoreBoardChallenge": ("/#/score-board", "not_available", "GET"),
    "tokenSaleChallenge": ("/#/tokensale-ico-ea", "not_available", "GET"),
    "privacyPolicyProofChallenge": ("/rest/user/privacy-security/privacy-policy", "not_available", "GET"),
    "privacyPolicyChallenge": ("/#/privacy-security/privacy-policy", "not_available", "GET"),
    "fileWriteChallenge": ("/ftp/legal.md", "file", "POST"),
    "jwtForgedChallenge": ("/rest/user/login", "Authorization", "GET"),
    "jwtUnsignedChallenge": ("/rest/user/login", "Authorization", "GET"),
    "rceChallenge": ("/rest/user/data-export", "format", "POST"),
    "rceOccupyChallenge": ("/rest/user/data-export", "format", "POST"),
    "nestedRceChallenge": ("/rest/user/data-export", "format", "POST"),
    "xxeFileDisclosureChallenge": ("/rest/products/upload", "file", "POST"),
    "xxeDosChallenge": ("/rest/products/upload", "file", "POST"),
    "captchaBypassChallenge": ("/api/Feedbacks", "captchaId", "POST"),
    "extraLanguageChallenge": ("/assets/i18n/tlh_AA.json", "not_available", "GET"),
    "deprecatedInterfaceChallenge": ("/rest/order/b2b", "order", "POST"),
    "errorHandlingChallenge": ("/rest/products/search", "q", "GET"),
    "corsChallenge": ("/rest/user/authentication-details", "Origin", "GET"),
    "forgedCouponChallenge": ("/rest/basket/1/coupon", "coupon", "PUT"),
    "continueCodeChallenge": ("/rest/continue-code", "code", "PUT"),
    "vulnerableDockerImageChallenge": ("/docker", "not_available", "GET"),
    "iacLeakedKeyChallenge": ("/infrastructure", "not_available", "GET"),
    "chatbotPromptInjectionChallenge": ("/rest/chatbot/respond", "message", "POST"),
    "chatbotGreedyInjectionChallenge": ("/rest/chatbot/respond", "message", "POST"),
    "basketAccessChallenge": ("/rest/basket/:id", "id", "GET"),
    "viewBasketChallenge": ("/rest/basket/:id", "id", "GET"),
    "deluxeFraudChallenge": ("/rest/deluxe-membership", "paymentMode", "POST"),
    "christmasSpecialChallenge": ("/rest/products/search", "q", "GET"),
    "orderHistoryChallenge": ("/rest/order-history", "id", "GET")
}


def map_difficulty_to_severity(difficulty: int, category: str) -> str:
    """Map Juice Shop difficulty (1-6) to standard CVSS-aligned Severity."""
    if difficulty <= 1:
        return "Low"
    elif difficulty == 2:
        if category in ["Broken Access Control", "Broken Authentication", "Injection"]:
            return "Medium"
        return "Low"
    elif difficulty == 3:
        return "Medium"
    elif difficulty == 4:
        return "High"
    elif difficulty >= 5:
        return "Critical"
    return "Medium"


def map_vulnerability_classification(category: str, key: str, name: str) -> Tuple[str, str]:
    """Map Juice Shop challenge category & key to canonical vulnerability type and CWE."""
    key_lower = key.lower()
    name_lower = name.lower()

    if category == "Injection":
        if "nosql" in key_lower or "nosql" in name_lower:
            return CATEGORY_CWE_MAPPING["Injection"]["nosql"]
        elif "prompt" in key_lower or "chatbot" in key_lower:
            return CATEGORY_CWE_MAPPING["Injection"]["prompt"]
        elif "xee" in key_lower or "xml" in key_lower:
            return CATEGORY_CWE_MAPPING["Injection"]["xee"]
        elif "template" in key_lower or "ssti" in key_lower:
            return CATEGORY_CWE_MAPPING["Injection"]["ssti"]
        return CATEGORY_CWE_MAPPING["Injection"]["default"]

    cat_map = CATEGORY_CWE_MAPPING.get(category, {})
    return cat_map.get("default", ("Other_Vulnerability", "CWE-699"))


class JuiceShopHarvester:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url.rstrip('/')
        self.client = httpx.Client(base_url=self.base_url, timeout=8.0)

    def is_alive(self) -> bool:
        """Check if local Juice Shop instance is responding."""
        try:
            r = self.client.get("/api/Challenges/?")
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Cannot connect to Juice Shop at {self.base_url}: {e}")
            return False

    def fetch_all_challenges(self) -> List[Dict[str, Any]]:
        """Fetch all challenge metadata from Juice Shop REST API."""
        resp = self.client.get("/api/Challenges/?")
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", [])

    def fetch_snippet(self, key: str) -> Optional[str]:
        """Fetch code snippet for coding challenge."""
        try:
            r = self.client.get(f"/snippets/{key}")
            if r.status_code == 200:
                return r.json().get("snippet")
        except Exception as e:
            logger.debug(f"Failed to fetch snippet for {key}: {e}")
        return None

    def discover_vulnerable_lines(self, key: str, snippet: str) -> List[int]:
        """Discover exact vulnerable lines by querying the verdict endpoint."""
        try:
            # Submit initial probe line
            res = self.client.post("/snippets/verdict", json={"key": key, "selectedLines": [1]}).json()
            if res.get("verdict") is True:
                return [1]
            hint = res.get("hint", "")
            # Extract line numbers from hints like 'Lines 3,5 are responsible...'
            nums = [int(n) for n in re.findall(r'\b\d+\b', hint)]
            if nums:
                # Verify exact lines
                ver = self.client.post("/snippets/verdict", json={"key": key, "selectedLines": nums}).json()
                if ver.get("verdict") is True:
                    return sorted(nums)
        except Exception as e:
            logger.debug(f"Error discovering vulnerable lines for {key}: {e}")
        return []

    def fetch_and_verify_fixes(self, key: str) -> Tuple[List[str], Optional[int], Optional[str]]:
        """
        Fetch candidate fixes and verify which patch is mathematically correct.
        Returns: (fixes_list, correct_fix_index, correct_fix_explanation)
        """
        try:
            r = self.client.get(f"/snippets/fixes/{key}")
            if r.status_code != 200:
                return [], None, None
            fixes = r.json().get("fixes", [])
            correct_idx = None
            correct_explanation = None

            for i, _ in enumerate(fixes):
                v_res = self.client.post("/snippets/fixes", json={"key": key, "selectedFix": i}).json()
                if v_res.get("verdict") is True:
                    correct_idx = i
                    correct_explanation = v_res.get("explanation")
                    break

            return fixes, correct_idx, correct_explanation
        except Exception as e:
            logger.debug(f"Error fetching fixes for {key}: {e}")
            return [], None, None

    def generate_validation_test(self, vuln_type: str, endpoint: str, parameter: str, http_method: str, challenge_name: str) -> str:
        """Generate a reproducible validation test command or payload to verify the fix."""
        if endpoint in ["unknown", "not_available"]:
            return "not_available"

        if vuln_type == "SQL_Injection":
            return f"curl -s -X {http_method} '{self.base_url}{endpoint}?{parameter}='\''%20OR%201=1--' | grep -v 'error' && echo 'Vulnerable' || echo 'Fixed'"
        elif vuln_type == "Cross_Site_Scripting":
            return f"curl -s -X {http_method} '{self.base_url}{endpoint}' -d '{parameter}=<script>alert(1)</script>' | grep -q '<script>alert(1)</script>' && echo 'Vulnerable' || echo 'Fixed'"
        elif vuln_type == "Broken_Access_Control":
            return f"curl -s -o /dev/null -w '%{{http_code}}' '{self.base_url}{endpoint}' | grep -q '401\\|403' && echo 'Fixed' || echo 'Vulnerable'"
        elif vuln_type == "Sensitive_Data_Exposure":
            return f"curl -s '{self.base_url}{endpoint}' | grep -q -E 'password|secret|key|admin' && echo 'Vulnerable' || echo 'Fixed'"
        elif vuln_type == "XML_External_Entity":
            xml_payload = '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>'
            return f"curl -s -X POST '{self.base_url}{endpoint}' -H 'Content-Type: application/xml' -d '{xml_payload}' | grep -q 'root:' && echo 'Vulnerable' || echo 'Fixed'"
        else:
            return f"curl -s -X {http_method} '{self.base_url}{endpoint}'"

    def harvest_dataset(self) -> List[Dict[str, Any]]:
        """Harvest, enrich, and validate all challenge records into the target dataset schema."""
        if not self.is_alive():
            raise ConnectionError(f"Juice Shop instance is not reachable at {self.base_url}")

        raw_challenges = self.fetch_all_challenges()
        logger.info(f"Retrieved {len(raw_challenges)} challenges from Juice Shop API.")

        records = []
        for c in raw_challenges:
            key = c.get("key", "")
            name = c.get("name", "unknown")
            category = c.get("category", "Miscellaneous")
            difficulty = c.get("difficulty", 1)
            raw_desc = c.get("description", "")
            # Clean HTML tags from description
            clean_desc = re.sub(r'<[^>]+>', '', raw_desc).strip()

            vuln_type, cwe = map_vulnerability_classification(category, key, name)
            severity = map_difficulty_to_severity(difficulty, category)

            # Endpoint, parameter, HTTP method extraction
            if key in KNOWN_ROUTES_MAP:
                endpoint, parameter, http_method = KNOWN_ROUTES_MAP[key]
            else:
                # Attempt regex extraction from description
                m_ep = re.search(r'(/[a-zA-Z0-9_\-/#]+)', raw_desc)
                endpoint = m_ep.group(1) if m_ep else "unknown"
                parameter = "unknown"
                http_method = "GET" if "/#" in endpoint or "/ftp" in endpoint else "unknown"

            source_code = "not_available"
            evidence = f"Juice Shop challenge [{name}] demonstrates {vuln_type} ({cwe}) under {category}."
            patch = "not_available"
            validation_test = "not_available"
            regression_result = "not_tested"

            # Check if this is a coding challenge with code snippet & fixes
            if c.get("hasCodingChallenge"):
                snippet = self.fetch_snippet(key)
                if snippet:
                    source_code = snippet
                    vuln_lines = self.discover_vulnerable_lines(key, snippet)
                    fixes, correct_idx, correct_expl = self.fetch_and_verify_fixes(key)

                    if correct_idx is not None and 0 <= correct_idx < len(fixes):
                        patch = fixes[correct_idx]
                        if correct_expl:
                            evidence = f"Vulnerable code located at line(s) {vuln_lines}. Security Root Cause & Remediation: {correct_expl}"
                        else:
                            evidence = f"Vulnerable code located at line(s) {vuln_lines}. Secure patch verified via Juice Shop challenge engine."
                    elif fixes:
                        patch = fixes[0]
                        evidence = f"Vulnerable code at line(s) {vuln_lines}. Proposed patch pending manual verification."

                    validation_test = self.generate_validation_test(vuln_type, endpoint, parameter, http_method, name)
            else:
                validation_test = self.generate_validation_test(vuln_type, endpoint, parameter, http_method, name)

            record = {
                "sample_id": f"juiceshop_{len(records):04d}",
                "data_source": "owasp_juiceshop",
                "challenge_name": name,
                "vulnerability_type": vuln_type,
                "cwe": cwe,
                "severity": severity,
                "description": clean_desc,
                "endpoint": endpoint,
                "parameter": parameter,
                "http_method": http_method,
                "source_code": source_code,
                "evidence": evidence,
                "patch": patch,
                "validation_test": validation_test,
                "regression_result": regression_result
            }
            records.append(record)

        logger.info(f"Successfully processed {len(records)} structured vulnerability records.")
        return records

    def save_dataset(self, records: List[Dict[str, Any]]) -> Tuple[str, str]:
        """Save dataset to standard CSV and JSON formats."""
        csv_path = os.path.join(DATA_DIR, "juiceshop_vulnerabilities.csv")
        json_path = os.path.join(DATA_DIR, "juiceshop_vulnerabilities.json")

        headers = [
            "sample_id",
            "data_source",
            "challenge_name",
            "vulnerability_type",
            "cwe",
            "severity",
            "description",
            "endpoint",
            "parameter",
            "http_method",
            "source_code",
            "evidence",
            "patch",
            "validation_test",
            "regression_result"
        ]

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for r in records:
                writer.writerow(r)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)

        logger.info(f"Juice Shop dataset saved to:\n  - CSV:  {csv_path}\n  - JSON: {json_path}")
        return csv_path, json_path


def generate_juiceshop_dataset() -> List[Dict[str, Any]]:
    """Entry point to run automated harvester and save dataset."""
    harvester = JuiceShopHarvester()
    records = harvester.harvest_dataset()
    harvester.save_dataset(records)
    return records


if __name__ == "__main__":
    records = generate_juiceshop_dataset()
    print(f"\nGenerated {len(records)} vulnerability records.")
    print("Sample record 1:")
    print(json.dumps(records[0], indent=2))
