"""
Model Training Script for Web Vulnerability Classifier.
Trains a high-performance, calibrated multi-class and anomaly classifier on vyykaaa/dataset-v2.
Saves model artifacts to `models/` directory for fast production inference.
"""

import os
import time
import json
import joblib
import numpy as np
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, accuracy_score, f1_score
from training.dataset_loader import prepare_dataset

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
os.makedirs(MODELS_DIR, exist_ok=True)


def build_pipeline() -> Pipeline:
    """
    Build a dual-feature extraction pipeline combining sub-word character n-grams and word tokens
    paired with a calibrated multi-class linear classifier.
    """
    vectorizer = FeatureUnion([
        ('char_ngrams', TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 5),
            min_df=3,
            max_features=40000,
            sublinear_tf=True
        )),
        ('word_ngrams', TfidfVectorizer(
            analyzer='word',
            token_pattern=r'(?u)\b\w+\b|[<>\'\"/\\=;:\(\)\{\}\[\]\$\&\|\`\-\+]',
            ngram_range=(1, 2),
            min_df=3,
            max_features=20000,
            sublinear_tf=True
        ))
    ])

    base_clf = SGDClassifier(
        loss='log_loss',
        penalty='l2',
        alpha=1e-5,
        max_iter=1000,
        tol=1e-4,
        random_state=42,
        class_weight='balanced'
    )

    calibrated_clf = CalibratedClassifierCV(
        estimator=base_clf,
        method='isotonic',
        cv=3
    )

    pipeline = Pipeline([
        ('vectorizer', vectorizer),
        ('classifier', calibrated_clf)
    ])

    return pipeline


def train_and_save(sample_limit: int = 150000):
    """
    Train vulnerability classification model on train split and evaluate on test split.
    """
    print(f"=== Starting Model Training Pipeline ===")
    start_time = time.time()
    
    print("1. Loading and normalizing training split...")
    X_train, y_train, train_meta = prepare_dataset("train", sample_limit=sample_limit)
    print(f"Loaded {len(X_train)} training requests across {len(train_meta['classes'])} classes.")
    
    print("\n2. Loading test split for evaluation...")
    X_test, y_test, test_meta = prepare_dataset("test")
    print(f"Loaded {len(X_test)} test requests.")
    
    print("\n3. Building feature extraction and calibrated model pipeline...")
    pipeline = build_pipeline()
    
    print(f"4. Training classifier on {len(X_train)} samples...")
    t0 = time.time()
    pipeline.fit(X_train, y_train)
    fit_duration = time.time() - t0
    print(f"Training completed in {fit_duration:.2f} seconds.")
    
    print("\n5. Evaluating model on test set...")
    t1 = time.time()
    y_pred = pipeline.predict(X_test)
    eval_duration = time.time() - t1
    
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    print(f"\n--- EVALUATION RESULTS ---")
    print(f"Accuracy:    {acc * 100:.2f}%")
    print(f"Macro F1:    {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")
    print(f"Inference latency: {eval_duration / len(X_test) * 1000:.3f} ms/sample")
    
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    # Save artifacts
    model_path = os.path.join(MODELS_DIR, "vuln_classifier.joblib")
    print(f"\n6. Saving model pipeline to {model_path}...")
    joblib.dump(pipeline, model_path, compress=3)
    
    report_path = os.path.join(MODELS_DIR, "eval_report.json")
    summary = {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "classes": list(pipeline.classes_),
        "num_training_samples": len(X_train),
        "num_test_samples": len(X_test),
        "training_time_sec": fit_duration,
        "classification_report": report_dict
    }
    
    with open(report_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Evaluation report saved to {report_path}")
    
    print(f"\n=== Training Pipeline Complete in {time.time() - start_time:.2f}s ===")
    return pipeline, summary


if __name__ == '__main__':
    train_and_save()
