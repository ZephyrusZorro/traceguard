"""Calibrated Prompt-Injection ML Classifier (Word + Char TF-IDF + Calibrated LogisticRegression)."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import FeatureUnion, Pipeline

from traceguard.config import settings
from traceguard.ml.dataset import InjectionSample, generate_injection_dataset


class InjectionDetectorModel:
    """Calibrated text classifier for detecting indirect prompt injections in tool outputs."""

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or (settings.models_dir / "injection_detector.joblib")
        self.pipeline: Pipeline | None = None
        self.metrics: dict[str, Any] = {}

    def _build_pipeline(self) -> Pipeline:
        features = FeatureUnion(
            [
                ("word_tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=4000, sublinear_tf=True)),
                ("char_tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=6000, sublinear_tf=True)),
            ]
        )
        base_clf = LogisticRegression(C=2.0, max_iter=1000, class_weight="balanced", random_state=42)
        calibrated = CalibratedClassifierCV(base_clf, method="sigmoid", cv=3)
        return Pipeline([("features", features), ("clf", calibrated)])

    def train(self, samples: list[InjectionSample] | None = None) -> dict[str, Any]:
        samples = samples or generate_injection_dataset(seed=42)
        train_s = [s for s in samples if s.split == "train"]
        val_s = [s for s in samples if s.split == "val"]
        test_s = [s for s in samples if s.split == "test"]

        self.pipeline = self._build_pipeline()
        X_train = [s.text for s in train_s]
        y_train = np.array([s.label for s in train_s])
        self.pipeline.fit(X_train, y_train)

        def eval_split(split_samples: list[InjectionSample]) -> dict[str, float]:
            X = [s.text for s in split_samples]
            y = np.array([s.label for s in split_samples])
            probs = self.pipeline.predict_proba(X)[:, 1]  # type: ignore[union-attr]
            preds = (probs >= 0.5).astype(int)
            hard_neg_idx = [i for i, s in enumerate(split_samples) if s.category == "HARD_NEGATIVE"]
            hard_neg_fpr = (
                float(np.mean(preds[hard_neg_idx] == 1)) if hard_neg_idx else 0.0
            )
            return {
                "precision": round(float(precision_score(y, preds, zero_division=0)), 4),
                "recall": round(float(recall_score(y, preds, zero_division=0)), 4),
                "f1": round(float(f1_score(y, preds, zero_division=0)), 4),
                "roc_auc": round(float(roc_auc_score(y, probs)), 4),
                "hard_negative_fpr": round(hard_neg_fpr, 4),
            }

        # Keyword baseline for comparison on test split
        kw_triggers = ("ignore all previous", "ignore previous", "system override", "exfiltrate", "shell_exec", "disregard", "bypass")
        y_test = np.array([s.label for s in test_s])
        kw_preds = np.array([1 if any(k in s.text.lower() for k in kw_triggers) else 0 for s in test_s])
        hard_neg_idx = [i for i, s in enumerate(test_s) if s.category == "HARD_NEGATIVE"]
        kw_hn_fpr = float(np.mean(kw_preds[hard_neg_idx] == 1)) if hard_neg_idx else 0.0

        self.metrics = {
            "dataset_sizes": {"train": len(train_s), "val": len(val_s), "test": len(test_s)},
            "val": eval_split(val_s),
            "test": eval_split(test_s),
            "keyword_baseline_test": {
                "precision": round(float(precision_score(y_test, kw_preds, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, kw_preds, zero_division=0)), 4),
                "f1": round(float(f1_score(y_test, kw_preds, zero_division=0)), 4),
                "hard_negative_fpr": round(kw_hn_fpr, 4),
            },
        }
        self.save()
        return self.metrics

    def save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": self.pipeline, "metrics": self.metrics}, self.model_path)

    def load_or_train(self) -> None:
        if self.model_path.exists():
            blob = joblib.load(self.model_path)
            self.pipeline = blob["pipeline"]
            self.metrics = blob.get("metrics", {})
        else:
            self.train()

    def predict_proba(self, text: str) -> float:
        if self.pipeline is None:
            self.load_or_train()
        if not text or not text.strip():
            return 0.0
        prob = float(self.pipeline.predict_proba([text])[0, 1])  # type: ignore[union-attr]
        return round(prob, 4)

    def predict_batch(self, texts: list[str]) -> list[float]:
        if self.pipeline is None:
            self.load_or_train()
        if not texts:
            return []
        safe = [t if t and t.strip() else "empty" for t in texts]
        probs = self.pipeline.predict_proba(safe)[:, 1]  # type: ignore[union-attr]
        return [round(float(p), 4) if t and t.strip() else 0.0 for p, t in zip(probs, texts)]
