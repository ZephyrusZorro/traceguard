"""Trained Step-Fault Ranker (HistGradientBoosting) and MAST Failure-Mode Classifier (RandomForest)."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

from traceguard.config import settings
from traceguard.core.causal_graph import build_causal_graph
from traceguard.core.security_firewall import CapabilityFirewall
from traceguard.ml.dataset import TraceSample, generate_trace_benchmark
from traceguard.ml.features import FEATURE_NAMES, extract_trace_features
from traceguard.schemas import MastMode, TraceIngestRequest


class AttributionModelSuite:
    """Trains and serves the step-level root-cause ranker and MAST mode classifier."""

    def __init__(
        self,
        model_path: Path | None = None,
        firewall: CapabilityFirewall | None = None,
    ) -> None:
        self.model_path = model_path or (settings.models_dir / "attribution_suite.joblib")
        self.firewall = firewall or CapabilityFirewall()
        self.step_ranker: HistGradientBoostingClassifier | None = None
        self.mast_classifier: RandomForestClassifier | None = None
        self.mode_classes: list[str] = []

    def _featurize_trace(self, trace: TraceIngestRequest) -> tuple[np.ndarray, list[list[str]], dict[str, Any]]:
        sec = self.firewall.audit_trace(trace.spans)
        tainted_set = set(sec["tainted_steps"])
        _, graph_dict = build_causal_graph(trace.spans, sec["injection_probs"], tainted_set)
        X, signals = extract_trace_features(
            trace,
            sec["injection_probs"],
            tainted_set,
            graph_dict["metrics"]["downstream_errors"],
        )
        return X, signals, {"security": sec, "graph": graph_dict}

    def train(self, dataset: list[TraceSample] | None = None) -> dict[str, Any]:
        dataset = dataset or generate_trace_benchmark(seed=42)
        train_traces = [d for d in dataset if d.split == "train"]

        X_steps_list: list[np.ndarray] = []
        y_steps_list: list[np.ndarray] = []
        X_mode_list: list[np.ndarray] = []
        y_mode_list: list[str] = []

        for sample in train_traces:
            X, _, _ = self._featurize_trace(sample.trace)
            y = np.zeros(len(X), dtype=int)
            if 0 <= sample.ground_truth_step < len(X):
                y[sample.ground_truth_step] = 1
                # MAST classifier uses attributed step features concatenated with trace-level max/mean stats
                trace_summary = np.concatenate([X[sample.ground_truth_step], np.max(X, axis=0)])
                X_mode_list.append(trace_summary)
                y_mode_list.append(sample.ground_truth_mode.value)
            X_steps_list.append(X)
            y_steps_list.append(y)

        X_all = np.vstack(X_steps_list)
        y_all = np.concatenate(y_steps_list)

        # Class-balanced sample weights so rare root-cause steps are weighted accurately
        pos_weight = float(np.sum(y_all == 0)) / max(1.0, float(np.sum(y_all == 1)))
        sample_weights = np.where(y_all == 1, pos_weight, 1.0)

        self.step_ranker = HistGradientBoostingClassifier(
            max_iter=120,
            max_depth=5,
            learning_rate=0.08,
            min_samples_leaf=8,
            random_state=42,
        )
        self.step_ranker.fit(X_all, y_all, sample_weight=sample_weights)

        X_mode = np.vstack(X_mode_list)
        self.mast_classifier = RandomForestClassifier(
            n_estimators=160,
            max_depth=10,
            class_weight="balanced",
            random_state=42,
        )
        self.mast_classifier.fit(X_mode, y_mode_list)
        self.mode_classes = list(self.mast_classifier.classes_)

        self.save()
        return {
            "train_traces": len(train_traces),
            "train_spans": int(len(y_all)),
            "feature_count": len(FEATURE_NAMES),
            "mast_classes": self.mode_classes,
        }

    def save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "step_ranker": self.step_ranker,
                "mast_classifier": self.mast_classifier,
                "mode_classes": self.mode_classes,
            },
            self.model_path,
        )

    def load_or_train(self) -> None:
        if self.model_path.exists():
            blob = joblib.load(self.model_path)
            self.step_ranker = blob["step_ranker"]
            self.mast_classifier = blob["mast_classifier"]
            self.mode_classes = blob["mode_classes"]
        else:
            self.train()

    def score_steps(
        self,
        X: np.ndarray,
    ) -> tuple[np.ndarray, str, float]:
        """Score every span in a trace and predict the MAST failure mode for the top step."""
        if self.step_ranker is None or self.mast_classifier is None:
            self.load_or_train()

        probs = self.step_ranker.predict_proba(X)[:, 1]  # type: ignore[union-attr]
        top_idx = int(np.argmax(probs))
        mode_vec = np.concatenate([X[top_idx], np.max(X, axis=0)]).reshape(1, -1)
        mode_probs = self.mast_classifier.predict_proba(mode_vec)[0]  # type: ignore[union-attr]
        best_m = int(np.argmax(mode_probs))
        pred_mode = str(self.mast_classifier.classes_[best_m])  # type: ignore[union-attr]
        mode_conf = float(mode_probs[best_m])
        return probs, pred_mode, mode_conf

    def predict_mode_for_step(self, X: np.ndarray, step_idx: int) -> tuple[str, float]:
        if self.mast_classifier is None:
            self.load_or_train()
        mode_vec = np.concatenate([X[step_idx], np.max(X, axis=0)]).reshape(1, -1)
        mode_probs = self.mast_classifier.predict_proba(mode_vec)[0]  # type: ignore[union-attr]
        best_m = int(np.argmax(mode_probs))
        return str(self.mast_classifier.classes_[best_m]), float(mode_probs[best_m])  # type: ignore[union-attr]
