"""
Unified Model Training Pipeline for Cybersecurity Vulnerability Detection.
Trains a high-performance, calibrated multi-class and anomaly classifier on the unified dataset
(combining OWASP Juice Shop application vulnerability metadata and Hugging Face HTTP signatures).
"""

import os
import time
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, accuracy_score, f1_score, precision_score, recall_score
from training.unified_pipeline import build_unified_dataset, UNIFIED_CSV

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
os.makedirs(MODELS_DIR, exist_ok=True)
MODEL_ARTIFACT_PATH = os.path.join(MODELS_DIR, "unified_vuln_classifier.joblib")
REPORT_PATH = os.path.join(MODELS_DIR, "unified_eval_report.json")


def build_vectorizer() -> FeatureUnion:
    """Build dual-feature extraction pipeline combining sub-word character n-grams and word tokens."""
    token_regex = r'(?u)\b\w+\b|[<>\'\"/\\=;:(){}\[\]$&|`\-\+]'

    return FeatureUnion([
        ('char_ngrams', TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 5),
            min_df=2,
            max_features=50000,
            sublinear_tf=True
        )),
        ('word_tokens', TfidfVectorizer(
            analyzer='word',
            token_pattern=token_regex,
            ngram_range=(1, 2),
            min_df=2,
            max_features=25000,
            sublinear_tf=True
        ))
    ])


def train_unified_model():
    """Execute model training on train split and evaluate on validation and test splits."""
    print("=== Starting Unified Cybersecurity Model Training Pipeline ===")
    start_time = time.time()

    if not os.path.exists(UNIFIED_CSV):
        print("Unified dataset not found on disk. Generating now...")
        df_all, _ = build_unified_dataset()
    else:
        df_all = pd.read_csv(UNIFIED_CSV)
        print(f"Loaded {len(df_all)} records from {UNIFIED_CSV}")

    # Prepare splits
    train_df = df_all[df_all['split'] == 'train']
    val_df = df_all[df_all['split'] == 'validation']
    test_df = df_all[df_all['split'] == 'test']

    print(f"Data Splits: Train={len(train_df)} | Val={len(val_df)} | Test={len(test_df)}")

    X_train = train_df['input_representation'].astype(str).tolist()
    y_train = train_df['vulnerability_type'].values

    X_val = val_df['input_representation'].astype(str).tolist()
    y_val = val_df['vulnerability_type'].values

    X_test = test_df['input_representation'].astype(str).tolist()
    y_test = test_df['vulnerability_type'].values

    print("\n1. Building feature extraction vectorizer...")
    vectorizer = build_vectorizer()

    print(f"2. Extracting TF-IDF features on {len(X_train)} training and {len(X_val)} validation samples...")
    t0 = time.time()
    X_train_vec = vectorizer.fit_transform(X_train)
    X_val_vec = vectorizer.transform(X_val)
    X_test_vec = vectorizer.transform(X_test)
    vec_duration = time.time() - t0
    print(f"Feature extraction complete in {vec_duration:.2f}s.")

    print(f"3. Fitting SGD multi-class classifier on training set across {len(np.unique(y_train))} classes...")
    t1 = time.time()
    base_clf = SGDClassifier(
        loss='log_loss',
        penalty='l2',
        alpha=1e-5,
        max_iter=1000,
        tol=1e-4,
        random_state=42,
        class_weight='balanced'
    )
    base_clf.fit(X_train_vec, y_train)

    print("4. Calibrating probabilities on validation set (isotonic regression)...")
    # Calibrate on validation set for robust probability estimation
    calibrated_clf = CalibratedClassifierCV(
        estimator=base_clf,
        method='isotonic',
        cv='prefit'
    )
    calibrated_clf.fit(X_val_vec, y_val)
    fit_duration = time.time() - t1
    print(f"Model training and calibration completed in {fit_duration:.2f}s.")

    pipeline = Pipeline([
        ('vectorizer', vectorizer),
        ('classifier', calibrated_clf)
    ])

    print("\n5. Evaluating on Holdout Test Split...")
    t2 = time.time()
    test_preds = pipeline.predict(X_test)
    eval_duration = time.time() - t2

    test_acc = accuracy_score(y_test, test_preds)
    test_macro_f1 = f1_score(y_test, test_preds, average='macro', zero_division=0)
    test_weighted_f1 = f1_score(y_test, test_preds, average='weighted', zero_division=0)
    test_precision = precision_score(y_test, test_preds, average='weighted', zero_division=0)
    test_recall = recall_score(y_test, test_preds, average='weighted', zero_division=0)

    print("\n" + "="*60)
    print("TEST SET BENCHMARK RESULTS")
    print("="*60)
    print(f"Accuracy:          {test_acc * 100:.2f}%")
    print(f"Weighted Precision:{test_precision:.4f}")
    print(f"Weighted Recall:   {test_recall:.4f}")
    print(f"Weighted F1:       {test_weighted_f1:.4f}")
    print(f"Macro F1:          {test_macro_f1:.4f}")
    print(f"Avg Inference Latency: {eval_duration / len(X_test) * 1000:.3f} ms/sample")

    report_dict = classification_report(y_test, test_preds, output_dict=True, zero_division=0)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, test_preds, zero_division=0))

    # Save model artifact
    print(f"\n6. Saving model artifact to {MODEL_ARTIFACT_PATH}...")
    joblib.dump(pipeline, MODEL_ARTIFACT_PATH, compress=3)

    summary = {
        "model_path": MODEL_ARTIFACT_PATH,
        "classes": list(pipeline.classes_),
        "num_classes": len(pipeline.classes_),
        "num_train_samples": len(X_train),
        "num_val_samples": len(X_val),
        "num_test_samples": len(X_test),
        "training_time_sec": fit_duration,
        "metrics": {
            "accuracy": test_acc,
            "weighted_precision": test_precision,
            "weighted_recall": test_recall,
            "weighted_f1": test_weighted_f1,
            "macro_f1": test_macro_f1,
            "latency_ms_per_sample": (eval_duration / len(X_test)) * 1000.0
        },
        "classification_report": report_dict
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Evaluation report saved to {REPORT_PATH}")

    print(f"\n=== Training Complete in {time.time() - start_time:.2f}s ===")
    return pipeline, summary


if __name__ == "__main__":
    train_unified_model()
