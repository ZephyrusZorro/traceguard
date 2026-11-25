"""CaMeL-Inspired Taint-Aware Information Flow & Capability Policy Firewall.

Separates trusted user control flow from untrusted external tool outputs and tracks
secret provenance across multi-agent steps to detect & block indirect prompt injection
and unauthorized data exfiltration.
"""
from __future__ import annotations

import re
from typing import Any

from traceguard.ml.injection_model import InjectionDetectorModel
from traceguard.schemas import ProvenanceLabel, SecurityViolation, SpanIn

DEFAULT_EXTERNAL_SINKS = frozenset(
    {"send_email", "http_post", "webhook_send", "transfer_funds", "shell_exec", "delete_records"}
)
SECRET_PATTERNS = re.compile(
    r"(SECRET_TOKEN|sk-live-[a-zA-Z0-9]+|PRIVATE_KEY|bearer\s+token|ssn|password|credentials)",
    re.IGNORECASE,
)


class CapabilityFirewall:
    """Evaluates provenance taint propagation and enforces capability boundaries."""

    def __init__(self, injection_model: InjectionDetectorModel | None = None) -> None:
        self.injection_model = injection_model or InjectionDetectorModel()
        self.injection_model.load_or_train()

    def audit_trace(
        self,
        spans: list[SpanIn],
        active_policies: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        ordered = sorted(spans, key=lambda s: s.step_index)
        active_policies = active_policies or []

        # Aggregate policy settings
        blocked_when_tainted = set(DEFAULT_EXTERNAL_SINKS)
        forbid_secret_external = True
        inj_threshold = 0.62
        for pol in active_policies:
            if pol.get("status") != "ACTIVE":
                continue
            rule = pol.get("rule", {})
            blocked_when_tainted.update(rule.get("blocked_tools_when_tainted", []))
            if "max_injection_threshold" in rule:
                inj_threshold = min(inj_threshold, float(rule["max_injection_threshold"]))

        # Score all span outputs & inputs with calibrated ML Injection Detector
        texts = [f"{s.input_text}\n{s.output_text}".strip() for s in ordered]
        probs = self.injection_model.predict_batch(texts)

        tainted_steps: set[int] = set()
        taint_sources: list[str] = []
        secret_seen = False
        violations: list[SecurityViolation] = []

        for s, prob in zip(ordered, probs):
            if s.provenance == ProvenanceLabel.SECRET_DATA or SECRET_PATTERNS.search(s.output_text):
                secret_seen = True

            # Rule 1: Untrusted tool output carrying indirect prompt injection
            if s.provenance == ProvenanceLabel.UNTRUSTED_TOOL and prob >= inj_threshold:
                tainted_steps.add(s.step_index)
                taint_sources.append(f"step-{s.step_index}:{s.tool_name or s.agent_name}")
                violations.append(
                    SecurityViolation(
                        step_index=s.step_index,
                        agent_name=s.agent_name,
                        rule_id="CAP-001-INDIRECT-INJECTION",
                        severity="HIGH",
                        injection_probability=prob,
                        taint_sources=[f"step-{s.step_index}"],
                        sink_tool=s.tool_name,
                        explanation=(
                            f"Untrusted tool '{s.tool_name}' emitted payload flagged as indirect prompt injection "
                            f"(calibrated p={prob:.2f} >= {inj_threshold:.2f}). Taint lattice marked active."
                        ),
                    )
                )

            # Propagate taint to downstream derived/tool spans once introduced
            if taint_sources and s.step_index > min(tainted_steps, default=999999):
                if s.provenance in (ProvenanceLabel.DERIVED, ProvenanceLabel.UNTRUSTED_TOOL):
                    tainted_steps.add(s.step_index)

            # Rule 2: CaMeL Control/Data Flow Capability Violation — tainted flow invoking external sink
            is_sink = (
                (s.tool_name in blocked_when_tainted)
                or bool(s.attributes.get("external_sink"))
            )
            carries_secret = (
                bool(s.attributes.get("contains_secret"))
                or bool(SECRET_PATTERNS.search(s.input_text))
                or (secret_seen and is_sink and s.step_index in tainted_steps)
            )
            if is_sink and s.step_index in tainted_steps:
                sev = "CRITICAL" if (forbid_secret_external and carries_secret) else "HIGH"
                violations.append(
                    SecurityViolation(
                        step_index=s.step_index,
                        agent_name=s.agent_name,
                        rule_id="CAP-002-TAINTED-SINK-EXFILTRATION" if carries_secret else "CAP-003-TAINTED-TOOL-CALL",
                        severity=sev,
                        injection_probability=max(prob, max((probs[t] for t in tainted_steps if t < len(probs)), default=prob)),
                        taint_sources=list(taint_sources),
                        sink_tool=s.tool_name,
                        explanation=(
                            f"Capability violation: agent '{s.agent_name}' invoked external sink '{s.tool_name}' "
                            f"under tainted control flow ({', '.join(taint_sources)})"
                            + (" with SECRET_DATA in context." if carries_secret else ".")
                        ),
                    )
                )

            # Rule 3: Role / Tool Allowlist Boundary Violation
            allowed = s.attributes.get("allowed_tools")
            if allowed and s.tool_name and s.tool_name not in allowed:
                violations.append(
                    SecurityViolation(
                        step_index=s.step_index,
                        agent_name=s.agent_name,
                        rule_id="CAP-004-ROLE-TOOL-BOUNDARY",
                        severity="MEDIUM",
                        injection_probability=prob,
                        taint_sources=[],
                        sink_tool=s.tool_name,
                        explanation=(
                            f"Agent '{s.agent_name}' invoked '{s.tool_name}', which is outside its declared "
                            f"capability allowlist {allowed}."
                        ),
                    )
                )

        if any(v.severity == "CRITICAL" for v in violations):
            verdict = "COMPROMISED"
        elif any(v.severity == "HIGH" for v in violations):
            verdict = "VIOLATION_BLOCKED"
        elif violations:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "verdict": verdict,
            "injection_probs": probs,
            "tainted_steps": sorted(tainted_steps),
            "violations": violations,
        }

    def evaluate_redteam_payload(
        self,
        payload: str,
        source_provenance: ProvenanceLabel,
        target_tool: str,
        contains_secret: bool,
    ) -> dict[str, Any]:
        """Interactive red-team test evaluating both ML injection model and CaMeL capability rules."""
        prob = self.injection_model.predict_proba(payload)
        tainted = source_provenance == ProvenanceLabel.UNTRUSTED_TOOL and prob >= 0.55
        is_sink = target_tool in DEFAULT_EXTERNAL_SINKS
        blocked = bool((tainted and is_sink) or (prob >= 0.72) or (tainted and contains_secret))

        reasons: list[str] = []
        if prob >= 0.55:
            reasons.append(f"ML Injection Classifier flagged payload (p={prob:.3f}).")
        if tainted and is_sink:
            reasons.append(f"CaMeL Capability Policy blocks untrusted tainted flow from invoking external sink '{target_tool}'.")
        if tainted and contains_secret:
            reasons.append("Information-Flow Lattice prevents SECRET_DATA co-existing with UNTRUSTED_TOOL control flow.")
        if not reasons:
            reasons.append("Payload passed ML injection check and capability flow invariants.")

        return {
            "decision": "BLOCK" if blocked else "ALLOW",
            "injection_probability": prob,
            "taint_active": tainted,
            "is_external_sink": is_sink,
            "capability_rule_triggered": "CAP-002-TAINTED-SINK-EXFILTRATION" if (tainted and is_sink and contains_secret) else ("CAP-001-INDIRECT-INJECTION" if blocked else "NONE"),
            "reasons": reasons,
        }
