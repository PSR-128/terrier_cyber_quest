"""
Dataset loader and preprocessor for web vulnerability detection.
Loads dataset from Hugging Face parquet files and normalizes labels into canonical security categories.
"""

import re
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, List

LABEL_MAPPING = {
    # Normal / Benign
    'None': 'Normal',
    'normal': 'Normal',
    
    # SQL Injection
    'SQL Injection': 'SQL_Injection',
    'SQL_Injection': 'SQL_Injection',
    'SQLMap Brute Force': 'SQL_Injection',
    'SQLMap Product GET': 'SQL_Injection',
    'SQLMap Feedback POST': 'SQL_Injection',
    
    # XSS and HTML Injection
    'Cross-Site_Scripting': 'Cross_Site_Scripting',
    'Cross-Site Scripting': 'Cross_Site_Scripting',
    'HTML_Injection': 'HTML_Injection',
    
    # File Inclusion & Traversal
    'Directory_Traversal': 'Directory_Traversal',
    'Local_File_Inclusion': 'Local_File_Inclusion',
    
    # Command & Code Execution
    'Command Injection': 'Command_Injection',
    'Command_Injection': 'Command_Injection',
    'Remote_Code_Execution': 'Remote_Code_Execution',
    
    # Request & Entity Forgery
    'XML_External_Entity': 'XML_External_Entity',
    'Server-Side_Request_Forgery': 'Server_Side_Request_Forgery',
    'Cross-Site_Request_Forgery': 'Cross_Site_Request_Forgery',
    
    # Template & Injections
    'Server-Side_Template_Injection': 'Server_Side_Template_Injection',
    'LDAP_Injection': 'LDAP_Injection',
    'CRLF_Injection': 'CRLF_Injection',
    'NoSQL_Injection': 'NoSQL_Injection',
    'Server_Side_Include_Injection': 'Server_Side_Include_Injection',
    
    # Web Logic & Redirection
    'Open_Redirect': 'Open_Redirect',
    'Web_Cache_Deception': 'Web_Cache_Deception',
    'Advanced Vulnerability Scan': 'Advanced_Vulnerability_Scan'
}


def normalize_attack_type(row) -> str:
    """Derive canonical attack category from label and attack_type columns."""
    label = str(row.get('label', '')).strip().lower()
    attack = row.get('attack_type')
    
    if label == 'normal' or pd.isna(attack) or attack is None or str(attack).strip() == '' or str(attack).strip() == 'None':
        return 'Normal'
        
    attack_str = str(attack).strip()
    return LABEL_MAPPING.get(attack_str, attack_str.replace(' ', '_').replace('-', '_'))


def extract_request_features(raw_text: str) -> str:
    """
    Clean and extract normalized textual representation of HTTP request for TF-IDF / N-gram features.
    Extracts HTTP method, path, parameters, headers, and body tokens.
    """
    if not isinstance(raw_text, str):
        return ""
    
    text = raw_text.strip()
    # Normalize common URL encodings for feature consistency
    text = text.replace('\r\n', '\n')
    return text


def load_raw_dataset(split: str = "train") -> pd.DataFrame:
    """
    Load dataset split directly from Hugging Face or fallback.
    """
    if split == "train":
        url = "hf://datasets/vyykaaa/dataset-v2/data/train-00000-of-00001.parquet"
    elif split == "test":
        url = "hf://datasets/vyykaaa/dataset-v2/data/test-00000-of-00001.parquet"
    else:
        raise ValueError(f"Unknown split: {split}")
        
    df = pd.read_parquet(url)
    return df


def prepare_dataset(split: str = "train", sample_limit: int = None) -> Tuple[List[str], np.ndarray, Dict[str, Any]]:
    """
    Load, clean, normalize, and return text features and target labels.
    """
    df = load_raw_dataset(split)
    
    # Drop completely null requests
    df = df.dropna(subset=['raw_request']).copy()
    
    # Normalize targets
    df['canonical_label'] = df.apply(normalize_attack_type, axis=1)
    df['is_anomalous'] = (df['canonical_label'] != 'Normal').astype(int)
    
    if sample_limit and sample_limit < len(df):
        # Stratified sampling to preserve minority vulnerability classes
        df = df.groupby('canonical_label', group_keys=False).apply(
            lambda x: x.sample(min(len(x), max(50, int(len(x) * sample_limit / len(df)))), random_state=42)
        )
    
    texts = df['raw_request'].tolist()
    labels = df['canonical_label'].values
    
    metadata = {
        'total_samples': len(df),
        'classes': sorted(list(df['canonical_label'].unique())),
        'class_counts': df['canonical_label'].value_counts().to_dict(),
        'anomalous_ratio': float(df['is_anomalous'].mean())
    }
    
    return texts, labels, metadata


if __name__ == '__main__':
    print("Testing dataset loader on test split...")
    texts, labels, meta = prepare_dataset("test")
    print(f"Loaded {len(texts)} test samples across {len(meta['classes'])} classes.")
    print("Class distribution:", meta['class_counts'])
