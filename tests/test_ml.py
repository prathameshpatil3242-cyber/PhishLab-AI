"""
tests/test_ml.py
----------------
Tests for the machine-learning training and evaluation pipeline.

The model is trained into a temporary folder so your real models/ directory
is never touched.  Training on the bundled fictional dataset takes about a
second.
"""

import json
import os

import pytest

import config
from phishlab import train_model


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """Train once for this module and return the measured metrics."""
    folder = tmp_path_factory.mktemp("models")
    paths = {
        "dataset": config.Config.DATASET_PATH,
        "model": str(folder / "model.joblib"),
        "vectorizer": str(folder / "vectorizer.joblib"),
        "metrics": str(folder / "metrics.json"),
    }
    metrics = train_model.train(paths["dataset"], paths["model"],
                                paths["vectorizer"], paths["metrics"])
    return paths, metrics


def test_training_creates_artifacts(trained):
    paths, metrics = trained
    assert os.path.exists(paths["model"])
    assert os.path.exists(paths["vectorizer"])
    assert os.path.exists(paths["metrics"])


def test_metrics_are_measured_on_a_held_out_set(trained):
    _paths, metrics = trained
    assert metrics["test_samples"] > 0
    assert metrics["train_samples"] > 0
    # No data leakage: the test set must be a strict subset of the rows used.
    assert metrics["train_samples"] + metrics["test_samples"] == metrics["dataset_rows_used"]
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["precision_weighted"] <= 1.0
    assert 0.0 <= metrics["recall_weighted"] <= 1.0
    assert 0.0 <= metrics["f1_weighted"] <= 1.0
    assert "do NOT reflect real-world" in metrics["caveat"]


def test_saved_metrics_file_matches_returned_values(trained):
    paths, metrics = trained
    with open(paths["metrics"], "r", encoding="utf-8") as fh:
        saved = json.load(fh)
    assert saved["accuracy"] == metrics["accuracy"]
    assert saved["trained_at"]


def test_model_predicts_phishing_and_legitimate(trained):
    paths, _metrics = trained
    pipeline, error = train_model.load_model(paths["model"])
    assert error is None and pipeline is not None

    label, probs = train_model.predict(
        pipeline,
        "Urgent: verify your password within 24 hours or your account will be "
        "closed. Click the link to confirm your identity now.")
    assert label == "phishing"
    assert set(probs) == {"phishing", "legitimate"}
    assert abs(sum(probs.values()) - 1.0) < 0.01

    label2, _ = train_model.predict(
        pipeline,
        "Hello, the practical batch will meet in the library at 4 pm. "
        "Please bring your ID cards.")
    assert label2 == "legitimate"


def test_training_fails_cleanly_on_missing_dataset(tmp_path):
    with pytest.raises(train_model.TrainError) as exc:
        train_model.train(str(tmp_path / "missing.csv"),
                          str(tmp_path / "m.joblib"),
                          str(tmp_path / "v.joblib"),
                          str(tmp_path / "metrics.json"))
    assert "dataset not found" in str(exc.value).lower()


def test_training_fails_cleanly_on_bad_columns(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("foo,bar\n1,2\n3,4\n", encoding="utf-8")
    with pytest.raises(train_model.TrainError) as exc:
        train_model.train(str(bad), str(tmp_path / "m.joblib"),
                          str(tmp_path / "v.joblib"), str(tmp_path / "metrics.json"))
    assert "columns" in str(exc.value).lower()


def test_training_fails_cleanly_on_single_label(tmp_path):
    bad = tmp_path / "single.csv"
    rows = ["text,label"] + [f'"message number {i}",phishing' for i in range(30)]
    bad.write_text("\n".join(rows), encoding="utf-8")
    with pytest.raises(train_model.TrainError):
        train_model.train(str(bad), str(tmp_path / "m.joblib"),
                          str(tmp_path / "v.joblib"), str(tmp_path / "metrics.json"))


def test_missing_sklearn_style_error_is_reported(monkeypatch, tmp_path):
    """load_model must never raise — it returns (None, message)."""
    monkeypatch.setattr(train_model, "SKLEARN_AVAILABLE", False)
    monkeypatch.setattr(train_model, "SKLEARN_ERROR", "simulated failure")
    pipeline, error = train_model.load_model(str(tmp_path / "model.joblib"))
    assert pipeline is None
    assert "simulated failure" in error
    monkeypatch.undo()
