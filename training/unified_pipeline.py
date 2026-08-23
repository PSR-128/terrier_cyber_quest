"""
Unified Dataset Pipeline for Cybersecurity Vulnerability Detection.
Integrates OWASP Juice Shop structured dataset with Hugging Face (vyykaaa/dataset-v2).
Performs schema harmonization, label normalization, deduplication, missing value handling,
and leak-free stratified Train / Validation / Test splitting.
"""

import os
import re
import json
import csv
import logging
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("unified_pipeline")

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
JUICESHOP_CSV = os.path.join(DATA_DIR, "juiceshop_vulnerabilities.csv")
UNIFIED_JSON = os.path.join(DATA_DIR, "unified_vulnerability_dataset.json")
UNIFIED_CSV = os.path.join(DATA_DIR, "unified_vulnerability_dataset.csv")

# Canonical Label to CWE and Severity mapping
ATTACK_TYPE_NORMALIZATION = {
    # Benign
    'None': ('Normal', 'None', 'Benign'),
    'normal': ('Normal', 'None', 'Benign'),
    
    # SQL Injection
    'SQL Injection': ('SQL_Injection', 'CWE-89', 'High'),
    'SQL_Injection': ('SQL_Injection', 'CWE-89', 'High'),
    'SQLMap Brute Force': ('SQL_Injection', 'CWE-89', 'High'),
    'SQLMap Product GET': ('SQL_Injection', 'CWE-89', 'High'),
    'SQLMap Feedback POST': ('SQL_Injection', 'CWE-89', 'High'),
    
    # XSS and HTML Injection
    'Cross-Site_Scripting': ('Cross_Site_Scripting', 'CWE-79', 'Medium'),
    'Cross-Site Scripting': ('Cross_Site_Scripting', 'CWE-79', 'Medium'),
    'Cross_Site_Scripting': ('Cross_Site_Scripting', 'CWE-79', 'Medium'),
    'HTML_Injection': ('Cross_Site_Scripting', 'CWE-79', 'Medium'),
    
    # Traversal & Inclusion
    'Directory_Traversal': ('Directory_Traversal', 'CWE-22', 'High'),
    'Local_File_Inclusion': ('Directory_Traversal', 'CWE-22', 'High'),
    
    # Command & Code Execution
    'Command Injection': ('Command_Injection', 'CWE-78', 'Critical'),
    'Command_Injection': ('Command_Injection', 'CWE-78', 'Critical'),
    'Remote_Code_Execution': ('Command_Injection', 'CWE-78', 'Critical'),
    
    # XXE & SSRF & CSRF
    'XML_External_Entity': ('XML_External_Entity', 'CWE-611', 'High'),
    'Server-Side_Request_Forgery': ('Server_Side_Request_Forgery', 'CWE-918', 'High'),
    'Server_Side_Request_Forgery': ('Server_Side_Request_Forgery', 'CWE-918', 'High'),
    'Cross-Site_Request_Forgery': ('Cross_Site_Request_Forgery', 'CWE-352', 'Medium'),
    'Cross_Site_Request_Forgery': ('Cross_Site_Request_Forgery', 'CWE-352', 'Medium'),
    
    # Injections
    'Server-Side_Template_Injection': ('Server_Side_Template_Injection', 'CWE-1336', 'High'),
    'Server_Side_Template_Injection': ('Server_Side_Template_Injection', 'CWE-1336', 'High'),
    'LDAP_Injection': ('LDAP_Injection', 'CWE-90', 'High'),
    'CRLF_Injection': ('CRLF_Injection', 'CWE-113', 'Medium'),
    'NoSQL_Injection': ('NoSQL_Injection', 'CWE-943', 'High'),
    'Server_Side_Include_Injection': ('Server_Side_Include_Injection', 'CWE-97', 'High'),
    
    # Web Logic & Redirection
    'Open_Redirect': ('Unvalidated_Redirects', 'CWE-601', 'Medium'),
    'Unvalidated_Redirects': ('Unvalidated_Redirects', 'CWE-601', 'Medium'),
    'Web_Cache_Deception': ('Web_Cache_Deception', 'CWE-524', 'Medium'),
    'Advanced Vulnerability Scan': ('Vulnerability_Scanning', 'CWE-200', 'Low'),
    
    # Access Control, Auth & Secrets (Juice Shop alignment)
    'Broken_Access_Control': ('Broken_Access_Control', 'CWE-285', 'High'),
    'Sensitive_Data_Exposure': ('Sensitive_Data_Exposure', 'CWE-200', 'Medium'),
    'Broken_Authentication': ('Broken_Authentication', 'CWE-287', 'High'),
    'Improper_Input_Validation': ('Improper_Input_Validation', 'CWE-20', 'Medium'),
    'Security_Misconfiguration': ('Security_Misconfiguration', 'CWE-16', 'Medium'),
    'Insecure_Deserialization': ('Insecure_Deserialization', 'CWE-502', 'Critical'),
    'Cryptographic_Issues': ('Cryptographic_Issues', 'CWE-327', 'Medium'),
    'Broken_Anti_Automation': ('Broken_Anti_Automation', 'CWE-799', 'Low'),
    'Vulnerable_Components': ('Vulnerable_Components', 'CWE-1395', 'High'),
    'Security_through_Obscurity': ('Security_through_Obscurity', 'CWE-656', 'Low'),
    'Prompt_Injection': ('Prompt_Injection', 'CWE-77', 'High'),
    'Observability_Failures': ('Observability_Failures', 'CWE-778', 'Low'),
    'Miscellaneous_Security_Flaw': ('Miscellaneous_Security_Flaw', 'CWE-699', 'Low')
}


def parse_http_request(raw_request: str) -> Tuple[str, str, str]:
    """Parse HTTP method, path, and parameter from raw HTTP request string."""
    if not isinstance(raw_request, str) or not raw_request.strip():
        return "GET", "/", "none"
        
    lines = raw_request.strip().split("\n")
    first_line = lines[0].strip()
    parts = first_line.split(" ")
    method = parts[0] if len(parts) > 0 else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    
    # Extract query params
    param = "none"
    if "?" in path:
        query_part = path.split("?", 1)[1]
        param_match = re.findall(r'([a-zA-Z0-9_\-]+)=', query_part)
        if param_match:
            param = ",".join(param_match[:3])
    elif method.upper() in ["POST", "PUT", "PATCH"] and len(lines) > 1:
        # Check body for parameters
        body = lines[-1]
        param_match = re.findall(r'([a-zA-Z0-9_\-]+)=', body)
        if param_match:
            param = ",".join(param_match[:3])
        elif "{" in body:
            json_keys = re.findall(r'"([a-zA-Z0-9_\-]+)"\s*:', body)
            if json_keys:
                param = ",".join(json_keys[:3])
                
    return method, path.split("?")[0], param


def load_and_harmonize_hf_dataset(sample_limit: int = 60000) -> pd.DataFrame:
    """Load Hugging Face vyykaaa/dataset-v2 and normalize to unified schema."""
    logger.info("Loading Hugging Face dataset (vyykaaa/dataset-v2)...")
    url_train = "hf://datasets/vyykaaa/dataset-v2/data/train-00000-of-00001.parquet"
    url_test = "hf://datasets/vyykaaa/dataset-v2/data/test-00000-of-00001.parquet"
    
    df_train = pd.read_parquet(url_train)
    df_test = pd.read_parquet(url_test)
    df_raw = pd.concat([df_train, df_test], ignore_index=True)
    
    # Deduplicate raw requests
    df_raw = df_raw.dropna(subset=['raw_request']).drop_duplicates(subset=['raw_request']).copy()
    logger.info(f"Loaded {len(df_raw)} unique HTTP requests from Hugging Face.")
    
    # Sample if needed with class preservation
    if sample_limit and sample_limit < len(df_raw):
        df_raw = df_raw.groupby('attack_type', group_keys=False, dropna=False).apply(
            lambda x: x.sample(min(len(x), max(100, int(len(x) * sample_limit / len(df_raw)))), random_state=42)
        ).reset_index(drop=True)
        logger.info(f"Subsampled to {len(df_raw)} stratified records for efficient balanced training.")

    records = []
    for idx, row in df_raw.iterrows():
        raw_req = str(row['raw_request']).strip()
        label_raw = str(row.get('label', '')).strip().lower()
        attack_raw = str(row.get('attack_type', 'None')).strip()
        
        if label_raw == 'normal' or attack_raw in ['None', 'none', 'nan', '']:
            canonical_label, cwe, severity = ('Normal', 'None', 'Benign')
            is_vuln = 0
        else:
            norm = ATTACK_TYPE_NORMALIZATION.get(attack_raw)
            if norm:
                canonical_label, cwe, severity = norm
            else:
                canonical_label = attack_raw.replace(' ', '_').replace('-', '_')
                cwe = 'CWE-699'
                severity = 'Medium'
            is_vuln = 1
            
        method, endpoint, param = parse_http_request(raw_req)
        
        record = {
            "sample_id": f"hf_req_{idx:06d}",
            "data_source": "huggingface_vyykaaa_v2",
            "challenge_name": "HTTP_Payload_Observation",
            "vulnerability_type": canonical_label,
            "cwe": cwe,
            "severity": severity,
            "description": f"Observed HTTP {method} request payload exhibiting signature of {canonical_label}.",
            "endpoint": endpoint,
            "parameter": param,
            "http_method": method,
            "source_code": "not_available",
            "evidence": f"HTTP traffic signature matches known attack pattern for {canonical_label}.",
            "patch": "not_available",
            "validation_test": "not_available",
            "regression_result": "not_tested",
            "input_representation": raw_req,
            "is_vulnerable": is_vuln
        }
        records.append(record)
        
    return pd.DataFrame(records)


def load_and_harmonize_juiceshop_dataset() -> pd.DataFrame:
    """Load generated Juice Shop dataset and harmonize to unified schema."""
    if not os.path.exists(JUICESHOP_CSV):
        raise FileNotFoundError(f"Juice Shop dataset not found at {JUICESHOP_CSV}. Run juiceshop_generator first.")
        
    df_js = pd.read_csv(JUICESHOP_CSV)
    logger.info(f"Loaded {len(df_js)} records from Juice Shop dataset.")
    
    records = []
    for idx, row in df_js.iterrows():
        vuln_type = str(row['vulnerability_type'])
        cwe = str(row['cwe'])
        sev = str(row['severity'])
        desc = str(row['description'])
        ep = str(row['endpoint'])
        param = str(row['parameter'])
        method = str(row['http_method'])
        src = str(row['source_code'])
        evidence = str(row['evidence'])
        patch = str(row['patch'])
        val_test = str(row['validation_test'])
        regr = str(row['regression_result'])
        chal_name = str(row['challenge_name'])
        
        # Construct rich input representation for ML training
        parts = [
            f"ENDPOINT: {ep}",
            f"METHOD: {method}",
            f"PARAMETER: {param}",
            f"DESCRIPTION: {desc}"
        ]
        if src not in ["not_available", "unknown"]:
            parts.append(f"SOURCE_CODE: {src[:300]}")
        if evidence not in ["not_available", "unknown"]:
            parts.append(f"EVIDENCE: {evidence[:200]}")
            
        input_rep = "\n".join(parts)
        
        record = {
            "sample_id": f"juiceshop_{idx:04d}",
            "data_source": "owasp_juiceshop",
            "challenge_name": chal_name,
            "vulnerability_type": vuln_type,
            "cwe": cwe,
            "severity": sev,
            "description": desc,
            "endpoint": ep,
            "parameter": param,
            "http_method": method,
            "source_code": src,
            "evidence": evidence,
            "patch": patch,
            "validation_test": val_test,
            "regression_result": regr,
            "input_representation": input_rep,
            "is_vulnerable": 1 if vuln_type != "Normal" else 0
        }
        records.append(record)
        
    return pd.DataFrame(records)


def stratified_split_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Split dataset into stratified 70% Train, 15% Validation, 15% Test robustly."""
    train_indices = []
    val_indices = []
    test_indices = []
    
    # Group by vulnerability_type and split deterministically per class
    for label, group in df.groupby('vulnerability_type'):
        idxs = group.index.tolist()
        np.random.seed(42)
        np.random.shuffle(idxs)
        n = len(idxs)
        
        if n == 1:
            train_indices.extend(idxs)
        elif n == 2:
            train_indices.append(idxs[0])
            test_indices.append(idxs[1])
        elif n == 3:
            train_indices.append(idxs[0])
            val_indices.append(idxs[1])
            test_indices.append(idxs[2])
        else:
            n_train = max(1, int(round(n * 0.70)))
            n_val = max(1, int(round(n * 0.15)))
            n_test = n - n_train - n_val
            if n_test <= 0:
                n_test = 1
                n_train = max(1, n - n_val - n_test)
                
            train_indices.extend(idxs[:n_train])
            val_indices.extend(idxs[n_train:n_train+n_val])
            test_indices.extend(idxs[n_train+n_val:])
            
    df = df.copy()
    df['split'] = 'unassigned'
    df.loc[train_indices, 'split'] = 'train'
    df.loc[val_indices, 'split'] = 'validation'
    df.loc[test_indices, 'split'] = 'test'
    
    return df


def build_unified_dataset() -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Combine both datasets, clean, normalize, handle missing values, and construct train/val/test splits."""
    df_hf = load_and_harmonize_hf_dataset()
    df_js = load_and_harmonize_juiceshop_dataset()
    
    logger.info("Combining Hugging Face and Juice Shop datasets...")
    df_combined = pd.concat([df_hf, df_js], ignore_index=True)
    
    # Deduplication and missing value validation
    df_combined = df_combined.drop_duplicates(subset=['input_representation']).copy().reset_index(drop=True)
    df_combined = df_combined.fillna('not_available')
    
    # Split
    df_final = stratified_split_dataset(df_combined)
    
    # Save unified datasets
    df_final.to_csv(UNIFIED_CSV, index=False, encoding='utf-8')
    df_final.to_json(UNIFIED_JSON, orient='records', indent=2)
    
    stats = {
        "total_records": len(df_final),
        "hf_records": int((df_final['data_source'] == 'huggingface_vyykaaa_v2').sum()),
        "juiceshop_records": int((df_final['data_source'] == 'owasp_juiceshop').sum()),
        "train_samples": int((df_final['split'] == 'train').sum()),
        "val_samples": int((df_final['split'] == 'validation').sum()),
        "test_samples": int((df_final['split'] == 'test').sum()),
        "classes": sorted(list(df_final['vulnerability_type'].unique())),
        "class_distribution": df_final['vulnerability_type'].value_counts().to_dict(),
        "severity_distribution": df_final['severity'].value_counts().to_dict(),
        "cwe_distribution": df_final['cwe'].value_counts().to_dict(),
        "missing_fields": {
            col: int((df_final[col].isin(['unknown', 'not_available', 'not_tested'])).sum())
            for col in df_final.columns
        }
    }
    
    logger.info(f"Unified dataset generated successfully with {len(df_final)} total records.")
    return df_final, stats


if __name__ == "__main__":
    df, stats = build_unified_dataset()
    print("\n=== UNIFIED DATASET STATISTICS ===")
    print(f"Total Records: {stats['total_records']}")
    print(f"  - Hugging Face: {stats['hf_records']}")
    print(f"  - Juice Shop:   {stats['juiceshop_records']}")
    print(f"Train / Val / Test Split: {stats['train_samples']} / {stats['val_samples']} / {stats['test_samples']}")
    print(f"Classes ({len(stats['classes'])}): {stats['classes']}")
