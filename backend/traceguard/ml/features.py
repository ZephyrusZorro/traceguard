"""22-Dimensional Structural, Causal, Semantic & Taint Feature Extractor for OTel GenAI Spans."""
from __future__ import annotations

import re
from typing import Any
import numpy as np

from traceguard.core.security_firewall import DEFAULT_EXTERNAL_SINKS
from traceguard.schemas import ProvenanceLabel, SpanIn, TraceIngestRequest

TOKEN_RE = re.compile(r"[a-zA-Z0-9_-]{3,}")
ENTITY_RE = re.compile(r"(INV-\d+|INC-\d+|PR-\d+|ENTITY-\d+|\$\d[\d,]*|#[0-9]+)")

FEATURE_NAMES: list[str] = [
    "rel_position",
    "is_first_step",
    "is_last_step",
    "op_is_tool",
    "op_is_chat",
    "op_is_verify",
    "status_error",
    "status_warning",
    "latency_zscore",
    "token_ratio",
    "token_drop_flag",
    "jaccard_prev_output",
    "repeat_agent_tool_count",
    "goal_lexical_overlap",
    "entity_retention_drop",
    "schema_violation_flag",
    "role_violation_flag",
    "taint_introduced",
    "taint_propagated",
    "capability_policy_violation",
    "injection_ml_prob",
    "downstream_error_fanout",
    "verifier_skip_flag",
]


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in TOKEN_RE.findall(text or "")}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / max(1, len(a | b))


def extract_trace_features(
    trace: TraceIngestRequest,
    injection_probs: list[float],
    tainted_steps: set[int],
    downstream_errors: dict[int, int],
) -> tuple[np.ndarray, list[list[str]]]:
    """Return (N x 23 feature matrix, per-step human-readable signal explanations)."""
    ordered = sorted(trace.spans, key=lambda s: s.step_index)
    n = len(ordered)
    goal_toks = _tokens(trace.root_goal)

    lats = np.array([s.latency_ms for s in ordered], dtype=float)
    lat_mean = float(np.mean(lats)) if n else 0.0
    lat_std = float(np.std(lats)) if n and float(np.std(lats)) > 1e-6 else 1.0

    rows: list[list[float]] = []
    signals_all: list[list[str]] = []
    seen_agent_tool: dict[tuple[str, str], int] = {}
    upstream_warning_or_incomplete = False

    for i, s in enumerate(ordered):
        sig: list[str] = []
        rel_pos = i / max(1, n - 1)
        is_first = 1.0 if i == 0 else 0.0
        is_last = 1.0 if i == n - 1 else 0.0
        op_tool = 1.0 if s.operation_name == "execute_tool" else 0.0
        op_chat = 1.0 if s.operation_name == "chat" else 0.0
        op_verify = 1.0 if s.operation_name == "verify" else 0.0
        status_err = 1.0 if s.status == "ERROR" else 0.0
        status_warn = 1.0 if s.status == "WARNING" else 0.0
        lat_z = float((s.latency_ms - lat_mean) / lat_std)
        tok_ratio = float(s.tokens_out / max(1, s.tokens_in))

        # Context reset / sharp token drop
        prev_tok_in = ordered[i - 1].tokens_in if i > 0 else s.tokens_in
        token_drop = 1.0 if (
            (i > 0 and prev_tok_in >= 150 and s.tokens_in < 0.25 * prev_tok_in)
            or bool(s.attributes.get("context_reset"))
            or "context reset" in s.output_text.lower()
            or "starting over with empty" in s.output_text.lower()
        ) else 0.0
        if token_drop:
            sig.append("context_reset_drop")

        # Loop repetition
        prev_out = _tokens(ordered[i - 1].output_text) if i > 0 else set()
        cur_out = _tokens(s.output_text)
        jacc_prev = _jaccard(cur_out, prev_out)
        key = (s.agent_name, s.tool_name or s.operation_name)
        seen_agent_tool[key] = seen_agent_tool.get(key, 0) + 1
        repeat_cnt = float(seen_agent_tool[key] - 1)
        # Check if THIS step starts a repeated sequence (lookahead 1 step for loop onset!)
        next_same = (
            i + 1 < n
            and ordered[i + 1].agent_name == s.agent_name
            and ordered[i + 1].tool_name == s.tool_name
            and _jaccard(cur_out, _tokens(ordered[i + 1].output_text)) > 0.65
        )
        if next_same and repeat_cnt == 0:
            repeat_cnt = 1.5
            sig.append("loop_onset_detected")
        elif repeat_cnt >= 1.0 or jacc_prev > 0.7:
            sig.append("step_repetition")

        goal_overlap = _jaccard(cur_out, goal_toks)

        # Information withholding: input has entities/high tokens but output is tiny/empty
        in_entities = set(ENTITY_RE.findall(s.input_text))
        out_entities = set(ENTITY_RE.findall(s.output_text))
        entity_drop = 1.0 if (
            (len(in_entities) >= 1 and len(out_entities) == 0 and s.tokens_out <= 30 and len(s.output_text) < 40)
            or bool(s.attributes.get("withheld_fields"))
        ) else 0.0
        if entity_drop:
            sig.append("info_withholding")

        # Schema / tool argument hallucination
        schema_viol = 1.0 if (
            bool(s.attributes.get("schema_violation"))
            or "schemavalidationerror" in s.output_text.lower()
            or "invalid_ccy" in s.input_text.lower()
            or "hallucinated" in s.input_text.lower()
        ) else 0.0
        if schema_viol:
            sig.append("tool_arg_schema_violation")

        # Role boundary violation
        allowed = s.attributes.get("allowed_tools")
        role_viol = 1.0 if (
            bool(s.attributes.get("role_boundary_crossed"))
            or (allowed and s.tool_name and s.tool_name not in allowed)
        ) else 0.0
        if role_viol:
            sig.append("role_boundary_violation")

        inj_prob = float(injection_probs[i]) if i < len(injection_probs) else 0.0
        taint_intro = 1.0 if (s.provenance == ProvenanceLabel.UNTRUSTED_TOOL and inj_prob >= 0.55) else 0.0
        taint_prop = 1.0 if (s.step_index in tainted_steps and not taint_intro) else 0.0
        is_sink = (s.tool_name in DEFAULT_EXTERNAL_SINKS) or bool(s.attributes.get("external_sink"))
        cap_viol = 1.0 if (is_sink and s.step_index in tainted_steps) else 0.0
        if taint_intro:
            sig.append(f"taint_introduced(p={inj_prob:.2f})")
        if cap_viol:
            sig.append("capability_sink_violation")

        ds_err = float(downstream_errors.get(s.step_index, 0)) / max(1, n)

        # Verifier skip / premature termination / superficial check
        approved_text = "approved" in s.output_text.lower()
        verifier_skip = 1.0 if (
            op_verify > 0.5
            and approved_text
            and (
                upstream_warning_or_incomplete
                or bool(s.attributes.get("premature_stop"))
                or bool(s.attributes.get("superficial_verify"))
            )
        ) else 0.0
        if verifier_skip:
            sig.append("verifier_superficial_or_premature_approval")

        if (
            s.status == "WARNING"
            or bool(s.attributes.get("artifact_incomplete"))
            or bool(s.attributes.get("semantic_mismatch"))
            or "not yet executed" in s.output_text.lower()
            or "mismatch" in s.output_text.lower()
        ):
            upstream_warning_or_incomplete = True

        rows.append([
            rel_pos,
            is_first,
            is_last,
            op_tool,
            op_chat,
            op_verify,
            status_err,
            status_warn,
            lat_z,
            tok_ratio,
            token_drop,
            jacc_prev,
            repeat_cnt,
            goal_overlap,
            entity_drop,
            schema_viol,
            role_viol,
            taint_intro,
            taint_prop,
            cap_viol,
            inj_prob,
            ds_err,
            verifier_skip,
        ])
        signals_all.append(sig)

    return np.array(rows, dtype=float), signals_all
