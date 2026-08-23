"""
Master Automation Pipeline for Autonomous Cybersecurity System.
Runs the complete dataset generation, harmonization, splitting, model training,
and generalization evaluation workflow in sequence against http://localhost:3000.
"""

import sys
import time
import json
import logging
from training.juiceshop_generator import generate_juiceshop_dataset
from training.unified_pipeline import build_unified_dataset
from training.train_unified import train_unified_model
from training.evaluate_unified import run_full_evaluation

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_pipeline")


def run_complete_pipeline():
    print("=" * 70)
    print("AUTONOMOUS CYBERSECURITY DATASET & MODEL TRAINING PIPELINE")
    print("=" * 70)
    start_time = time.time()

    # Step 1: Harvest OWASP Juice Shop Dataset
    print("\n>>> STEP 1: Harvesting Local OWASP Juice Shop Dataset (http://localhost:3000)...")
    t0 = time.time()
    js_records = generate_juiceshop_dataset()
    print(f"[OK] Step 1 Complete: Harvested {len(js_records)} structured Juice Shop records in {time.time()-t0:.2f}s.")

    # Step 2: Harmonize with Hugging Face and Build Unified Dataset
    print("\n>>> STEP 2: Harmonizing Hugging Face & Juice Shop Datasets...")
    t1 = time.time()
    unified_df, stats = build_unified_dataset()
    print(f"[OK] Step 2 Complete: Built unified dataset with {stats['total_records']} records in {time.time()-t1:.2f}s.")
    print(f"  - Train Split: {stats['train_samples']} samples (70%)")
    print(f"  - Val Split:   {stats['val_samples']} samples (15%)")
    print(f"  - Test Split:  {stats['test_samples']} samples (15%)")
    print(f"  - Canonical Classes: {len(stats['classes'])}")

    # Step 3: Train Vulnerability Detection Model
    print("\n>>> STEP 3: Training & Calibrating Vulnerability Detection Model...")
    t2 = time.time()
    pipeline, train_summary = train_unified_model()
    print(f"[OK] Step 3 Complete: Model trained and saved to models/ in {time.time()-t2:.2f}s.")

    # Step 4: Evaluate and Benchmark Generalization
    print("\n>>> STEP 4: Evaluating Holdout Test Set & Zero-Shot Generalization...")
    t3 = time.time()
    eval_report = run_full_evaluation()
    print(f"[OK] Step 4 Complete: Evaluation finished in {time.time()-t3:.2f}s.")

    total_duration = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"PIPELINE COMPLETED SUCCESSFULLY IN {total_duration:.2f} SECONDS")
    print("=" * 70)
    print(f"Overall Accuracy:       {eval_report['evaluation_summary']['accuracy']*100:.2f}%")
    print(f"Macro F1-Score:         {eval_report['evaluation_summary']['macro_f1']:.4f}")
    print(f"Generalization Score:   {eval_report['generalization_benchmark']['passed']}/{eval_report['generalization_benchmark']['total_test_cases']} ({eval_report['generalization_benchmark']['generalization_score_pct']:.1f}%)")
    print("Artifacts generated:")
    print("  - data/juiceshop_vulnerabilities.csv")
    print("  - data/juiceshop_vulnerabilities.json")
    print("  - data/unified_vulnerability_dataset.csv")
    print("  - data/unified_vulnerability_dataset.json")
    print("  - models/unified_vuln_classifier.joblib")
    print("  - models/unified_eval_report.json")


if __name__ == "__main__":
    run_complete_pipeline()
