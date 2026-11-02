"""
phishlab/train_model.py
-----------------------
Machine-learning pipeline for PhishLab AI.

Pipeline
--------
    CSV dataset  ->  pandas DataFrame  ->  train/test split (stratified)
                 ->  TF-IDF vectoriser (text -> numbers)
                 ->  Multinomial Naive Bayes classifier
                 ->  evaluation (accuracy, precision, recall, F1)
                 ->  artefacts saved to models/ (model.joblib + vectorizer.joblib)

KEY POINTS FOR STUDENTS
    * train_test_split(..., stratify=y) keeps the phishing/legitimate ratio
      the same in both splits.
    * The vectoriser is fit ONLY on the training data.  Fitting it on all
      data first would leak information from the test set (data leakage).
    * If anything fails, a TrainError with a readable message is raised —
      the app shows that message instead of pretending the AI worked.
"""

import json
import os
from datetime import datetime

# joblib is installed together with scikit-learn
import joblib

try:
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                                 recall_score, classification_report)
    from sklearn.model_selection import train_test_split
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
    SKLEARN_ERROR = ""
except Exception as exc:                     # pragma: no cover - env dependent
    SKLEARN_AVAILABLE = False
    SKLEARN_ERROR = str(exc)


class TrainError(Exception):
    """Raised when training cannot complete; carries a student-friendly message."""


def load_dataset(path):
    """Read the CSV and validate its columns/labels."""
    if not os.path.exists(path):
        raise TrainError(
            f"Dataset not found at '{path}'. Run: python data/make_dataset.py"
        )
    try:
        df = pd.read_csv(path)
    except Exception as exc:
        raise TrainError(f"Could not read the dataset CSV: {exc}")

    required = {"text", "label"}
    if not required.issubset(set(df.columns)):
        raise TrainError(
            f"Dataset must contain the columns {sorted(required)}; found {list(df.columns)}."
        )

    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()

    df = df[df["label"].isin(["phishing", "legitimate"])]

    if len(df) < 20:
        raise TrainError(
            f"Only {len(df)} usable rows found. At least 20 rows are required "
            "to create a meaningful train/test split."
        )
    if df["label"].nunique() < 2:
        raise TrainError("Dataset must contain both 'phishing' and 'legitimate' examples.")

    # Drop duplicate texts so the same sentence cannot appear in both splits.
    before = len(df)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    removed = before - len(df)
    return df, removed


def train(dataset_path, model_path, vectorizer_path, metrics_path, test_size=0.25,
          random_state=42, verbose=False):
    """
    Train the classifier and save all artefacts.

    Returns a dictionary with evaluation metrics and file locations.
    Raises TrainError with an explanation when training fails.
    """
    if not SKLEARN_AVAILABLE:
        raise TrainError(
            "scikit-learn/pandas could not be imported in this Python environment. "
            f"Install the requirements (pip install -r requirements.txt). Details: {SKLEARN_ERROR}"
        )

    df, removed_duplicates = load_dataset(dataset_path)

    texts = df["text"].tolist()
    labels = df["label"].tolist()

    try:
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels,
            test_size=test_size,
            random_state=random_state,
            stratify=labels,          # keeps class balance identical in both sets
        )
    except ValueError as exc:
        raise TrainError(f"Could not split the data: {exc}")

    if len(set(y_train)) < 2:
        raise TrainError(
            "The training split does not contain both classes. Add more examples "
            "to data/sample_messages.csv and try again."
        )

    # NOTE: fit the vectoriser ONLY on training text (prevents data leakage).
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            stop_words="english",      # removes 'the', 'and', ...
            ngram_range=(1, 2),        # single words and word pairs
            min_df=1,
            max_features=5000,
        )),
        ("clf", MultinomialNB(alpha=0.1)),
    ])

    try:
        pipeline.fit(X_train, y_train)
    except Exception as exc:
        raise TrainError(f"Model training failed: {exc}")

    try:
        y_pred = pipeline.predict(X_test)
    except Exception as exc:
        raise TrainError(f"Prediction failed after training: {exc}")

    labels_order = ["phishing", "legitimate"]
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted",
                                 labels=labels_order, zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted",
                             labels=labels_order, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted",
                        labels=labels_order, zero_division=0))
    report = classification_report(y_test, y_pred, labels=labels_order, zero_division=0,
                                   output_dict=True)

    # --- Save artefacts -------------------------------------------------
    try:
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(pipeline, model_path)
        # The vectoriser is inside the pipeline; also store a standalone copy
        # so students can inspect it separately.
        joblib.dump(pipeline.named_steps["tfidf"], vectorizer_path)
    except Exception as exc:
        raise TrainError(f"Could not save the trained model: {exc}")

    metrics = {
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_rows_used": int(len(df)),
        "duplicates_removed": int(removed_duplicates),
        "test_size": test_size,
        "test_samples": int(len(X_test)),
        "train_samples": int(len(X_train)),
        "accuracy": round(acc, 4),
        "precision_weighted": round(prec, 4),
        "recall_weighted": round(rec, 4),
        "f1_weighted": round(f1, 4),
        "classification_report": report,
        "model_type": "TF-IDF + Multinomial Naive Bayes",
        "caveat": (
            "These numbers come from a small fictional demonstration dataset. "
            "They do NOT reflect real-world phishing detection performance."
        ),
    }
    try:
        with open(metrics_path, "w", encoding="utf-8") as fh:
            json.dump(metrics, fh, indent=2)
    except Exception as exc:
        raise TrainError(f"Could not save the metrics file: {exc}")

    if verbose:
        print(f"Rows used      : {len(df)}")
        print(f"Train / test   : {len(X_train)} / {len(X_test)}")
        print(f"Accuracy       : {acc:.3f}")
        print(f"Precision (w)  : {prec:.3f}")
        print(f"Recall (w)     : {rec:.3f}")
        print(f"F1 (w)         : {f1:.3f}")

    return metrics


def load_metrics(metrics_path):
    """Return saved metrics or None when the model has never been trained."""
    if not os.path.exists(metrics_path):
        return None
    try:
        with open(metrics_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def load_model(model_path):
    """
    Return (pipeline, None) on success or (None, error_message) on failure.
    Never raises — callers show the error message to the user.
    """
    if not SKLEARN_AVAILABLE:
        return None, f"scikit-learn is not available: {SKLEARN_ERROR}"
    if not os.path.exists(model_path):
        return None, "No trained model found yet. Click 'Train model' first."
    try:
        pipeline = joblib.load(model_path)
        return pipeline, None
    except Exception as exc:
        return None, f"Could not load the trained model: {exc}"


def predict(pipeline, text):
    """
    Predict a single message.
    Returns (label, probabilities_dict) or raises TrainError.
    """
    if pipeline is None:
        raise TrainError("The model is not loaded.")
    text = (text or "").strip()
    if not text:
        raise TrainError("No text was provided for prediction.")
    try:
        label = str(pipeline.predict([text])[0])
        proba = pipeline.predict_proba([text])[0]
        classes = list(pipeline.classes_)
        probs = {cls: round(float(p), 4) for cls, p in zip(classes, proba)}
    except Exception as exc:
        raise TrainError(f"Prediction failed: {exc}")
    return label, probs


def status(metrics_path, model_path):
    """Small status object for the AI Model page."""
    metrics = load_metrics(metrics_path)
    model_exists = os.path.exists(model_path)
    return {
        "trained": bool(metrics and model_exists),
        "sklearn_available": SKLEARN_AVAILABLE,
        "sklearn_error": SKLEARN_ERROR,
        "metrics": metrics,
        "model_exists": model_exists,
    }


if __name__ == "__main__":     # `python -m phishlab.train_model`
    import config
    cfg = config.Config
    result = train(cfg.DATASET_PATH, cfg.MODEL_PATH, cfg.VECTORIZER_PATH,
                   cfg.METRICS_PATH, verbose=True)
    print(json.dumps({k: result[k] for k in
                      ("accuracy", "precision_weighted", "recall_weighted", "f1_weighted")},
                     indent=2))
