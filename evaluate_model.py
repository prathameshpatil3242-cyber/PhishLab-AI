#!/usr/bin/env python3
"""
evaluate_model.py
-----------------
Re-scores the SAVED model on the held-out test set.

Run it after training:

    python evaluate_model.py

It rebuilds exactly the same deterministic train/test split that
train_model.py created (same test_size and random_state), loads
models/model.joblib, and prints the measured metrics for the test rows
only.  Nothing is retrained, so the numbers describe how the saved model
performs on data it never saw during training.
"""

import sys

import config
from phishlab.train_model import (SKLEARN_AVAILABLE, SKLEARN_ERROR, TrainError,
                                  load_dataset, load_metrics, load_model)

try:
    from sklearn.metrics import (accuracy_score, classification_report,
                                 f1_score, precision_score, recall_score)
    from sklearn.model_selection import train_test_split
except Exception as exc:                     # pragma: no cover
    SKLEARN_AVAILABLE = False
    SKLEARN_ERROR = str(exc)

LABELS = ["phishing", "legitimate"]


def main():
    cfg = config.Config

    if not SKLEARN_AVAILABLE:
        print(f"EVALUATION FAILED: scikit-learn is not available ({SKLEARN_ERROR})",
              file=sys.stderr)
        return 1

    model, err = load_model(cfg.MODEL_PATH)
    if model is None:
        print(f"EVALUATION FAILED: {err}", file=sys.stderr)
        print("Train it first with:  python train_model.py", file=sys.stderr)
        return 1

    try:
        df, _removed = load_dataset(cfg.DATASET_PATH)
    except TrainError as exc:
        print(f"EVALUATION FAILED: {exc}", file=sys.stderr)
        return 1

    # Identical split to training (same test_size and random_state) so the
    # evaluation happens on held-out rows only.
    _X_train, X_test, y_train, y_test = train_test_split(
        df["text"].tolist(), df["label"].tolist(),
        test_size=0.25, random_state=42, stratify=df["label"].tolist(),
    )

    y_pred = list(model.predict(X_test))

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", labels=LABELS, zero_division=0)
    rec = recall_score(y_test, y_pred, average="weighted", labels=LABELS, zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", labels=LABELS, zero_division=0)

    print("PhishLab AI — evaluation of the saved model")
    print("-" * 55)
    print(f"held-out samples evaluated : {len(X_test)}")
    print(f"training rows seen by model: {len(y_train)}")
    print(f"accuracy                   : {acc:.4f}")
    print(f"precision (weighted)       : {prec:.4f}")
    print(f"recall    (weighted)       : {rec:.4f}")
    print(f"F1 score  (weighted)       : {f1:.4f}")
    print("-" * 55)
    print(classification_report(y_test, y_pred, labels=LABELS, zero_division=0))

    saved = load_metrics(cfg.METRICS_PATH)
    if saved:
        print(f"metrics.json recorded at training time: accuracy={saved['accuracy']}, "
              f"f1={saved['f1_weighted']} (trained {saved['trained_at']})")

    mismatches = [(t, p, s) for t, p, s in zip(y_test, y_pred, X_test) if t != p]
    if mismatches:
        print(f"\n{len(mismatches)} misclassified test message(s):")
        for true_label, pred, text in mismatches:
            preview = (text[:90] + "...") if len(text) > 90 else text
            print(f"  true={true_label:<11} predicted={pred:<11} {preview!r}")

    print("\nNOTE: this dataset is small and fictional; these figures do not "
          "describe real-world phishing detection performance.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
