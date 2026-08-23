"""
Standalone Model Evaluation Script.
Loads pre-trained model and benchmarks on test dataset, generating detailed per-class metrics.
"""

import os
import json
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from training.dataset_loader import prepare_dataset

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "vuln_classifier.joblib")


def run_evaluation():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Run train.py first.")
        
    print(f"Loading trained model from {MODEL_PATH}...")
    pipeline = joblib.load(MODEL_PATH)
    
    print("Loading test split (vyykaaa/dataset-v2)...")
    X_test, y_test, meta = prepare_dataset("test")
    print(f"Loaded {len(X_test)} test samples.")
    
    print("Running predictions...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    print("\n" + "="*50)
    print(f"MODEL BENCHMARK RESULTS")
    print("="*50)
    print(f"Accuracy:    {acc * 100:.2f}%")
    print(f"Macro F1:    {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")
    print("\nDetailed Per-Class Performance:")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    out_path = os.path.join(MODELS_DIR, "eval_report.json")
    with open(out_path, "w") as f:
        json.dump({
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "classes": list(pipeline.classes_),
            "classification_report": report_dict
        }, f, indent=2)
    print(f"Saved report to {out_path}")
    return report_dict


if __name__ == '__main__':
    run_evaluation()
