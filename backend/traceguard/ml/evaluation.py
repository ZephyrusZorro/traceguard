"""Objective ML Benchmark & Ablation Evaluation Harness for TraceGuard.

Evaluates 6 methods on the exact same held-out test split of TraceBench-MAS (72 traces)
and compares our Calibrated Injection Classifier vs Keyword Baseline on InjectBench-ToolIO.
Never fabricates metrics — every number is computed live from actual predictions.
"""
from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any
import numpy as np
from sklearn.metrics import f1_score

from traceguard.config import settings
from traceguard.core.causal_graph import build_causal_graph
from traceguard.core.counterfactual import infer_recommended_intervention, run_counterfactual_replay
from traceguard.core.security_firewall import CapabilityFirewall
from traceguard.ml.attribution_model import AttributionModelSuite
from traceguard.ml.dataset import TraceSample, generate_injection_dataset, generate_trace_benchmark
from traceguard.ml.features import FEATURE_NAMES, extract_trace_features
from traceguard.ml.injection_model import InjectionDetectorModel

# Indices of key features in FEATURE_NAMES for rule/drift baselines
_IDX = {name: i for i, name in enumerate(FEATURE_NAMES)}


def compute_rule_scores(X: np.ndarray) -> np.ndarray:
    """Baseline 3: Deterministic Rule-Only MAST heuristic (no ML ranker, no counterfactual)."""
    scores = (
        0.35 * X[:, _IDX["capability_policy_violation"]]
        + 0.30 * X[:, _IDX["role_violation_flag"]]
        + 0.30 * X[:, _IDX["schema_violation_flag"]]
        + 0.28 * X[:, _IDX["token_drop_flag"]]
        + 0.25 * X[:, _IDX["entity_retention_drop"]]
        + 0.25 * X[:, _IDX["verifier_skip_flag"]]
        + 0.20 * np.clip(X[:, _IDX["repeat_agent_tool_count"]] / 2.0, 0.0, 1.0)
        + 0.15 * X[:, _IDX["status_error"]]
    )
    return np.clip(scores, 0.0, 1.0)


def compute_drift_scores(X: np.ndarray) -> np.ndarray:
    """Baseline 4: Lexical/Goal Drift & Latency Anomaly score only."""
    goal_drift = 1.0 - X[:, _IDX["goal_lexical_overlap"]]
    lat_anom = np.clip(X[:, _IDX["latency_zscore"]] / 3.0, 0.0, 1.0)
    return np.clip(0.65 * goal_drift + 0.35 * lat_anom, 0.0, 1.0)


def expected_calibration_error(confidences: list[float], correct: list[int], n_bins: int = 10) -> float:
    """Compute Expected Calibration Error (ECE)."""
    if not confidences:
        return 0.0
    conf = np.array(confidences, dtype=float)
    acc = np.array(correct, dtype=float)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        mask = (conf >= bins[i]) & (conf < bins[i + 1] if i < n_bins - 1 else conf <= bins[i + 1])
        if np.any(mask):
            ece += (np.sum(mask) / len(conf)) * abs(float(np.mean(acc[mask])) - float(np.mean(conf[mask])))
    return round(float(ece), 4)


def run_full_benchmark(seed: int = 42, save_path: Path | None = None) -> dict[str, Any]:
    """Train all models cleanly on train split and evaluate all 6 methods on held-out test split."""
    inj_dataset = generate_injection_dataset(seed=seed)
    inj_model = InjectionDetectorModel()
    inj_metrics = inj_model.train(inj_dataset)

    firewall = CapabilityFirewall(injection_model=inj_model)
    trace_dataset = generate_trace_benchmark(seed=seed)
    suite = AttributionModelSuite(firewall=firewall)
    train_info = suite.train(trace_dataset)

    test_traces = [s for s in trace_dataset if s.split == "test"]
    rng = random.Random(seed)

    method_names = [
        "random_baseline",
        "last_error_heuristic",
        "lexical_drift_only",
        "rule_only_mast",
        "ml_ranker_only_ablation",
        "c3_attributor_full",
    ]
    results: dict[str, dict[str, Any]] = {
        m: {
            "top1_hits": 0,
            "top3_hits": 0,
            "agent_hits": 0,
            "mrr_sum": 0.0,
            "latencies_ms": [],
            "confidences": [],
            "correct_flags": [],
            "per_mode_hits": {},
            "per_mode_total": {},
        }
        for m in method_names
    }
    c3_true_modes: list[str] = []
    c3_pred_modes: list[str] = []
    cf_flip_count = 0

    for sample in test_traces:
        ordered = sorted(sample.trace.spans, key=lambda s: s.step_index)
        n = len(ordered)
        gt_step = sample.ground_truth_step
        gt_agent = sample.ground_truth_agent
        gt_mode = sample.ground_truth_mode.value

        t0 = time.perf_counter()
        sec = firewall.audit_trace(ordered)
        tainted_set = set(sec["tainted_steps"])
        _, graph_dict = build_causal_graph(ordered, sec["injection_probs"], tainted_set)
        X, _ = extract_trace_features(
            sample.trace,
            sec["injection_probs"],
            tainted_set,
            graph_dict["metrics"]["downstream_errors"],
        )
        feat_ms = (time.perf_counter() - t0) * 1000.0

        # 1. Random
        t_s = time.perf_counter()
        rand_scores = np.array([rng.random() for _ in range(n)])
        rand_ms = (time.perf_counter() - t_s) * 1000.0

        # 2. Last-Error / Last-Step Heuristic
        t_s = time.perf_counter()
        err_steps = [i for i, sp in enumerate(ordered) if sp.status == "ERROR"]
        last_scores = np.linspace(0.05, 0.5, n)
        if err_steps:
            last_scores[err_steps[-1]] = 0.95
        else:
            last_scores[-1] = 0.95
        last_ms = (time.perf_counter() - t_s) * 1000.0

        # 3. Lexical Drift Only
        t_s = time.perf_counter()
        drift_scores = compute_drift_scores(X)
        drift_ms = feat_ms + (time.perf_counter() - t_s) * 1000.0

        # 4. Rule-Only MAST
        t_s = time.perf_counter()
        rule_scores = compute_rule_scores(X)
        rule_ms = feat_ms + (time.perf_counter() - t_s) * 1000.0

        # 5. ML Ranker Only (Ablation without Counterfactual Replay)
        t_s = time.perf_counter()
        ml_probs, _, _ = suite.score_steps(X)
        ml_ms = feat_ms + (time.perf_counter() - t_s) * 1000.0

        # 6. Full C3-Attributor (ML Ranker + Counterfactual Verification over Top-3 candidates)
        t_s = time.perf_counter()
        top3_idx = list(np.argsort(-ml_probs)[:3])
        c3_scores = ml_probs.copy() * 0.55
        best_cf_flip = False
        for cand_idx in top3_idx:
            cand_mode, _ = suite.predict_mode_for_step(X, int(cand_idx))
            inv_type, patch = infer_recommended_intervention(ordered[int(cand_idx)], cand_mode)
            cf_res = run_counterfactual_replay(
                sample.trace,
                sample.trace.external_trace_id,
                int(cand_idx),
                inv_type,
                patch,
                tainted_set,
            )
            c3_scores[int(cand_idx)] = 0.55 * float(ml_probs[int(cand_idx)]) + 0.45 * cf_res.delta_score
            if int(cand_idx) == int(np.argmax(c3_scores)) and cf_res.causal_flip:
                best_cf_flip = True
        c3_ms = ml_ms + (time.perf_counter() - t_s) * 1000.0

        if best_cf_flip:
            cf_flip_count += 1

        c3_top = int(np.argmax(c3_scores))
        pred_mode, _ = suite.predict_mode_for_step(X, c3_top)
        c3_true_modes.append(gt_mode)
        c3_pred_modes.append(pred_mode)

        score_map = {
            "random_baseline": (rand_scores, rand_ms),
            "last_error_heuristic": (last_scores, last_ms),
            "lexical_drift_only": (drift_scores, drift_ms),
            "rule_only_mast": (rule_scores, rule_ms),
            "ml_ranker_only_ablation": (ml_probs, ml_ms),
            "c3_attributor_full": (c3_scores, c3_ms),
        }

        for m, (sc, lat) in score_map.items():
            ranked = list(np.argsort(-sc))
            top1 = int(ranked[0])
            hit1 = 1 if top1 == gt_step else 0
            hit3 = 1 if gt_step in ranked[:3] else 0
            agent_hit = 1 if ordered[top1].agent_name == gt_agent else 0
            rank_pos = ranked.index(gt_step) + 1 if gt_step in ranked else n
            rec = results[m]
            rec["top1_hits"] += hit1
            rec["top3_hits"] += hit3
            rec["agent_hits"] += agent_hit
            rec["mrr_sum"] += 1.0 / rank_pos
            rec["latencies_ms"].append(lat)
            rec["confidences"].append(float(np.clip(sc[top1], 0.0, 1.0)))
            rec["correct_flags"].append(hit1)
            rec["per_mode_hits"][gt_mode] = rec["per_mode_hits"].get(gt_mode, 0) + hit1
            rec["per_mode_total"][gt_mode] = rec["per_mode_total"].get(gt_mode, 0) + 1

    total_test = len(test_traces)
    summary_table: list[dict[str, Any]] = []
    for m in method_names:
        rec = results[m]
        summary_table.append(
            {
                "method": m,
                "top1_step_accuracy": round(rec["top1_hits"] / total_test, 4),
                "top3_step_accuracy": round(rec["top3_hits"] / total_test, 4),
                "agent_attribution_accuracy": round(rec["agent_hits"] / total_test, 4),
                "mrr": round(rec["mrr_sum"] / total_test, 4),
                "ece": expected_calibration_error(rec["confidences"], rec["correct_flags"]),
                "mean_latency_ms": round(float(np.mean(rec["latencies_ms"])), 2),
            }
        )

    per_mode_c3 = {
        mode: round(
            results["c3_attributor_full"]["per_mode_hits"].get(mode, 0)
            / max(1, results["c3_attributor_full"]["per_mode_total"].get(mode, 1)),
            4,
        )
        for mode in sorted(results["c3_attributor_full"]["per_mode_total"].keys())
    }

    report = {
        "seed": seed,
        "trace_benchmark": {
            "total_traces": len(trace_dataset),
            "train_traces": train_info["train_traces"],
            "val_traces": sum(1 for d in trace_dataset if d.split == "val"),
            "test_traces": total_test,
            "feature_count": train_info["feature_count"],
            "methods": summary_table,
            "c3_mast_macro_f1": round(float(f1_score(c3_true_modes, c3_pred_modes, average="macro", zero_division=0)), 4),
            "c3_counterfactual_recovery_rate": round(cf_flip_count / max(1, total_test), 4),
            "c3_per_mode_top1_accuracy": per_mode_c3,
        },
        "injection_benchmark": inj_metrics,
    }

    out_path = save_path or (settings.data_dir / "benchmark_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
