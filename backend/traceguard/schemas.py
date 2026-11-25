"""Typed Pydantic v2 contracts for OTel GenAI spans, C3-Attributor, Council Agents, and Policies."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field


class ProvenanceLabel(str, Enum):
    TRUSTED_USER = "TRUSTED_USER"
    UNTRUSTED_TOOL = "UNTRUSTED_TOOL"
    SECRET_DATA = "SECRET_DATA"
    DERIVED = "DERIVED"


class TraceStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    COMPROMISED = "COMPROMISED"


class MastPillar(str, Enum):
    SYSTEM_DESIGN = "Pillar 1: System Design & Specification"
    INTER_AGENT_MISALIGNMENT = "Pillar 2: Inter-Agent Misalignment"
    VERIFICATION_TERMINATION = "Pillar 3: Task Verification & Termination"
    SECURITY_INTEGRITY = "Security: Prompt Injection & Capability Violation"
    NONE = "None (Healthy Execution)"


class MastMode(str, Enum):
    HEALTHY = "HEALTHY"
    SPEC_ROLE_VIOLATION = "SPEC_ROLE_VIOLATION"
    SPEC_INFINITE_LOOP = "SPEC_INFINITE_LOOP"
    SPEC_CONTEXT_RESET = "SPEC_CONTEXT_RESET"
    MISALIGN_INFO_WITHHOLDING = "MISALIGN_INFO_WITHHOLDING"
    MISALIGN_TOOL_ARG_HALLUCINATION = "MISALIGN_TOOL_ARG_HALLUCINATION"
    VERIFY_PREMATURE_TERMINATION = "VERIFY_PREMATURE_TERMINATION"
    VERIFY_SUPERFICIAL_CHECK = "VERIFY_SUPERFICIAL_CHECK"
    SEC_INDIRECT_PROMPT_INJECTION = "SEC_INDIRECT_PROMPT_INJECTION"


MAST_MODE_TO_PILLAR: dict[MastMode, MastPillar] = {
    MastMode.HEALTHY: MastPillar.NONE,
    MastMode.SPEC_ROLE_VIOLATION: MastPillar.SYSTEM_DESIGN,
    MastMode.SPEC_INFINITE_LOOP: MastPillar.SYSTEM_DESIGN,
    MastMode.SPEC_CONTEXT_RESET: MastPillar.SYSTEM_DESIGN,
    MastMode.MISALIGN_INFO_WITHHOLDING: MastPillar.INTER_AGENT_MISALIGNMENT,
    MastMode.MISALIGN_TOOL_ARG_HALLUCINATION: MastPillar.INTER_AGENT_MISALIGNMENT,
    MastMode.VERIFY_PREMATURE_TERMINATION: MastPillar.VERIFICATION_TERMINATION,
    MastMode.VERIFY_SUPERFICIAL_CHECK: MastPillar.VERIFICATION_TERMINATION,
    MastMode.SEC_INDIRECT_PROMPT_INJECTION: MastPillar.SECURITY_INTEGRITY,
}


class SpanIn(BaseModel):
    """OpenTelemetry GenAI Semantic Convention aligned span."""
    span_id: str = Field(..., min_length=1, max_length=128)
    parent_span_id: str | None = None
    step_index: int = Field(..., ge=0)
    agent_name: str = Field(..., min_length=1, max_length=128)
    operation_name: Literal["invoke_agent", "chat", "execute_tool", "verify"] = "chat"
    tool_name: str | None = None
    input_text: str = Field(default="", max_length=20000)
    output_text: str = Field(default="", max_length=20000)
    provenance: ProvenanceLabel = ProvenanceLabel.TRUSTED_USER
    latency_ms: float = Field(default=50.0, ge=0.0)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    status: Literal["OK", "ERROR", "WARNING", "BLOCKED"] = "OK"
    attributes: dict[str, Any] = Field(default_factory=dict)


class TraceIngestRequest(BaseModel):
    external_trace_id: str = Field(..., min_length=1, max_length=128)
    idempotency_key: str | None = Field(default=None, max_length=128)
    scenario_name: str = Field(default="custom_trace", max_length=160)
    framework: str = Field(default="otel-genai", max_length=64)
    status: TraceStatus = TraceStatus.FAILED
    root_goal: str = Field(..., min_length=1, max_length=2000)
    spans: list[SpanIn] = Field(..., min_length=1, max_length=200)
    ground_truth_agent: str | None = None
    ground_truth_step: int | None = None
    ground_truth_mode: MastMode | None = None
    auto_diagnose: bool = True


class SecurityViolation(BaseModel):
    step_index: int
    agent_name: str
    rule_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    injection_probability: float = Field(..., ge=0.0, le=1.0)
    taint_sources: list[str] = Field(default_factory=list)
    sink_tool: str | None = None
    explanation: str


class StepAttributionScore(BaseModel):
    step_index: int
    span_id: str
    agent_name: str
    ml_fault_prob: float = Field(..., ge=0.0, le=1.0)
    rule_signal_score: float = Field(..., ge=0.0, le=1.0)
    injection_prob: float = Field(..., ge=0.0, le=1.0)
    counterfactual_delta: float | None = None
    combined_c3_score: float = Field(..., ge=0.0, le=1.0)
    tainted: bool = False
    key_signals: list[str] = Field(default_factory=list)


class AgentExecutionReport(BaseModel):
    """Explicit contract emitted by each specialist agent in the 4-Agent Council."""
    agent_name: str
    status: Literal["SUCCESS", "DEGRADED", "FAILED", "TIMEOUT"]
    duration_ms: float
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class CounterfactualRequest(BaseModel):
    intervention_step_index: int = Field(..., ge=0)
    intervention_type: Literal[
        "SANITIZE_TAINT",
        "RESTORE_CONTEXT",
        "BLOCK_UNAUTHORIZED_TOOL",
        "REPAIR_TOOL_ARGS",
        "FORCE_VERIFICATION",
        "BREAK_LOOP",
        "CUSTOM_PATCH",
    ] = "SANITIZE_TAINT"
    patched_content: str | None = Field(default=None, max_length=10000)


class CounterfactualResult(BaseModel):
    id: str
    trace_id: str
    intervention_step_index: int
    intervention_type: str
    patched_content: str
    original_outcome: str
    counterfactual_outcome: str
    causal_flip: bool
    delta_score: float = Field(..., ge=0.0, le=1.0)
    downstream_recovered_steps: int
    replayed_spans: list[dict[str, Any]]
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DiagnosisResult(BaseModel):
    id: str
    trace_id: str
    council_run_id: str
    attributed_agent: str
    attributed_step_index: int
    mast_pillar: str
    mast_mode: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    causal_verification_score: float = Field(..., ge=0.0, le=1.0)
    contradiction_detected: bool
    contradiction_note: str | None = None
    security_verdict: Literal["CLEAN", "SUSPICIOUS", "VIOLATION_BLOCKED", "COMPROMISED"]
    security_violations: list[SecurityViolation] = Field(default_factory=list)
    summary: str
    step_scores: list[StepAttributionScore] = Field(default_factory=list)
    agent_reports: list[AgentExecutionReport] = Field(default_factory=list)
    causal_graph: dict[str, Any] = Field(default_factory=dict)
    counterfactual: CounterfactualResult | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: str = Field(..., min_length=4, max_length=1000)
    blocked_tools_when_tainted: list[str] = Field(default_factory=list)
    forbid_secret_to_external: bool = True
    max_injection_threshold: float = Field(default=0.65, ge=0.1, le=0.99)
    allowed_agent_tools: dict[str, list[str]] = Field(default_factory=dict)


class RedTeamTestRequest(BaseModel):
    payload: str = Field(..., min_length=1, max_length=10000)
    source_provenance: ProvenanceLabel = ProvenanceLabel.UNTRUSTED_TOOL
    target_tool: str = Field(default="send_email", max_length=128)
    contains_secret_in_context: bool = True


class WebhookCreateRequest(BaseModel):
    target_url: str = Field(..., min_length=8, max_length=512)
    events: list[str] = Field(default_factory=lambda: ["diagnosis.completed", "security.alert"])
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"


class ScenarioRunRequest(BaseModel):
    scenario_key: str = Field(default="ebanking_prompt_injection")
    use_ollama: bool = False
    inject_controlled_failure: bool = False
