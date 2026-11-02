#!/usr/bin/env python3
"""
train_model.py
--------------
Trains the PhishLab AI text classifier and prints the measured results.

Run it from the project folder:

    python train_model.py

What happens:
    1. data/sample_messages.csv is loaded and checked (text + label columns).
    2. The data is split into training and held-out test sets (stratified).
    3. TF-IDF + Multinomial Naive Bayes is fit on the TRAINING data only.
    4. The model is evaluated on the TEST data it has never seen.
    5. models/model.joblib, models/vectorizer.joblib and models/metrics.json
       are saved.
    6. accuracy / precision / recall / F1 are printed — measured, not invented.
"""

import json
import sys

import config
from phishlab.train_model import TrainError, train


def main():
    cfg = config.Config
    print("PhishLab AI — training the classifier")
    print("-" * 50)
    try:
        metrics = train(cfg.DATASET_PATH, cfg.MODEL_PATH, cfg.VECTORIZER_PATH,
                        cfg.METRICS_PATH, verbose=True)
    except TrainError as exc:
        print(f"TRAINING FAILED: {exc}", file=sys.stderr)
        return 1

    print("-" * 50)
    print("Measured results on the held-out test set "
          f"({metrics['test_samples']} samples the model never saw):")
    print(f"  accuracy            : {metrics['accuracy']:.4f}")
    print(f"  precision (weighted): {metrics['precision_weighted']:.4f}")
    print(f"  recall    (weighted): {metrics['recall_weighted']:.4f}")
    print(f"  F1 score  (weighted): {metrics['f1_weighted']:.4f}")
    print(f"\n  saved to : {cfg.MODEL_PATH}")
    print(f"  metrics  : {cfg.METRICS_PATH}")
    print("\nNOTE:", metrics["caveat"])
    print("\nPer-class report:")
    report = metrics.get("classification_report", {})
    for label in ("phishing", "legitimate"):
        if label in report:
            row = report[label]
            print(f"  {label:<12} precision={row['precision']:.3f} "
                  f"recall={row['recall']:.3f} f1={row['f1-score']:.3f} "
                  f"support={int(row['support'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
