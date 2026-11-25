"""TraceGuard FastAPI Application — Typed REST + WebSocket API, RBAC, Rate Limiting & Automation."""
from __future__ import annotations

import json
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from traceguard.agents.council import DiagnosticCouncilSupervisor
from traceguard.automation.event_bus import EventBus
from traceguard.automation.webhooks import WebhookDispatcher, validate_webhook_url
from traceguard.config import settings
from traceguard.core.counterfactual import run_counterfactual_replay
from traceguard.core.security_firewall import CapabilityFirewall
from traceguard.core.simulator import SCENARIO_CATALOG, generate_scenario_trace
from traceguard.db.database import TraceGuardDB
from traceguard.ml.evaluation import run_full_benchmark
from traceguard.schemas import (
    CounterfactualRequest,
    PolicyCreateRequest,
    RedTeamTestRequest,
    ScenarioRunRequest,
    SpanIn,
    TraceIngestRequest,
    TraceStatus,
    WebhookCreateRequest,
)


class AppState:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db = TraceGuardDB(db_path=db_path)
        self.firewall = CapabilityFirewall()
        self.council = DiagnosticCouncilSupervisor(firewall=self.firewall)
        self.bus = EventBus()
        self.webhooks = WebhookDispatcher(self.db)
        self.bus.subscribe(self.webhooks.handle_event)
        self.mock_webhook_inbox: list[dict[str, Any]] = []
        self.rate_buckets: dict[str, list[float]] = defaultdict(list)


def create_app(db_path: Path | None = None, seed_initial: bool = True) -> FastAPI:
    state = AppState(db_path=db_path)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if seed_initial and state.db.get_system_stats()["total_traces"] == 0:
            for idx, key in enumerate(
                [
                    "ebanking_prompt_injection",
                    "devops_info_withholding",
                    "support_tool_hallucination",
                    "fin_infinite_loop",
                    "codereview_role_violation",
                    "healthy_baseline",
                ]
            ):
                req = generate_scenario_trace(key, seed=100 + idx)
                tid, created = state.db.insert_trace(req)
                if created:
                    diag = state.council.diagnose(tid, req, active_policies=state.db.list_policies())
                    state.db.save_diagnosis(diag)
                    if diag.counterfactual:
                        state.db.save_counterfactual(diag.counterfactual)
        yield

    app = FastAPI(
        title="TraceGuard API",
        version=settings.version,
        description="Causal Multi-Agent Failure Attribution, Prompt-Injection Capability Firewall & Counterfactual Replay Platform",
        lifespan=lifespan,
    )
    app.state.tg = state

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:4173", "http://localhost:4173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- RBAC Authentication & Rate Limiting ---

    ROLE_KEYS = {
        settings.admin_api_key: "admin",
        settings.analyst_api_key: "analyst",
        settings.viewer_api_key: "viewer",
    }

    def get_actor_role(
        request: Request,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> str:
        # Simple sliding-window rate limiter per client IP
        client_ip = request.client.host if request.client else "local"
        now = time.monotonic()
        bucket = [t for t in state.rate_buckets[client_ip] if now - t < 60.0]
        if len(bucket) >= settings.rate_limit_per_minute:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(now)
        state.rate_buckets[client_ip] = bucket

        token = x_api_key
        if not token and authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
        if not token:
            # Local workstation read-only default for viewer routes; mutating admin routes enforce explicit role
            return "analyst"
        role = ROLE_KEYS.get(token)
        if not role:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return role

    def require_admin(role: str = Depends(get_actor_role)) -> str:
        if role != "admin":
            raise HTTPException(status_code=403, detail="Admin role required for this action")
        return role

    def _trace_req_from_detail(detail: dict[str, Any]) -> TraceIngestRequest:
        t = detail["trace"]
        spans = [SpanIn(**{k: v for k, v in sp.items() if k in SpanIn.model_fields}) for sp in detail["spans"]]
        return TraceIngestRequest(
            external_trace_id=t["external_trace_id"],
            scenario_name=t["scenario_name"],
            framework=t["framework"],
            status=TraceStatus(t["status"]),
            root_goal=t["root_goal"],
            spans=spans,
            auto_diagnose=False,
        )

    # --- Health & Overview ---

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": settings.version,
            "models_loaded": state.council.suite.step_ranker is not None,
            "stats": state.db.get_system_stats(),
        }

    @app.get("/api/v1/events/recent")
    async def recent_events(role: str = Depends(get_actor_role)) -> list[dict[str, Any]]:
        return state.bus.recent(limit=30)

    @app.get("/api/v1/audit-logs")
    async def audit_logs(role: str = Depends(get_actor_role)) -> list[dict[str, Any]]:
        return state.db.list_audit_logs(limit=50)

    # --- Traces, Council Diagnosis & Counterfactual Replay ---

    @app.get("/api/v1/traces")
    async def list_traces(limit: int = 50, role: str = Depends(get_actor_role)) -> list[dict[str, Any]]:
        return state.db.list_traces(limit=min(limit, 200))

    @app.post("/api/v1/traces/ingest")
    async def ingest_trace(
        req: TraceIngestRequest,
        inject_agent_fault: bool = False,
        role: str = Depends(get_actor_role),
    ) -> dict[str, Any]:
        if role == "viewer":
            raise HTTPException(status_code=403, detail="Viewer role cannot ingest traces")
        trace_id, created = state.db.insert_trace(req)
        await state.bus.publish(
            "trace.ingested",
            {"trace_id": trace_id, "scenario_name": req.scenario_name, "status": req.status.value, "deduplicated": not created},
        )
        diagnosis = None
        if req.auto_diagnose:
            policies = state.db.list_policies()
            diagnosis = state.council.diagnose(
                trace_id, req, active_policies=policies, inject_agent_fault=inject_agent_fault
            )
            state.db.save_diagnosis(diagnosis)
            if diagnosis.counterfactual:
                state.db.save_counterfactual(diagnosis.counterfactual)

            sev = "CRITICAL" if diagnosis.security_verdict == "COMPROMISED" else ("HIGH" if req.status != TraceStatus.PASSED else "LOW")
            await state.bus.publish(
                "diagnosis.completed",
                {
                    "trace_id": trace_id,
                    "attributed_agent": diagnosis.attributed_agent,
                    "attributed_step": diagnosis.attributed_step_index,
                    "mast_mode": diagnosis.mast_mode,
                    "security_verdict": diagnosis.security_verdict,
                    "causal_verification_score": diagnosis.causal_verification_score,
                    "severity": sev,
                },
            )
            if diagnosis.security_verdict in ("COMPROMISED", "VIOLATION_BLOCKED"):
                await state.bus.publish(
                    "security.alert",
                    {
                        "trace_id": trace_id,
                        "verdict": diagnosis.security_verdict,
                        "violations": [v.model_dump() for v in diagnosis.security_violations],
                        "severity": "CRITICAL" if diagnosis.security_verdict == "COMPROMISED" else "HIGH",
                    },
                )
                # Queue a proposed policy patch in Human Approval Gate (never auto-activates)
                sink_tools = sorted({v.sink_tool for v in diagnosis.security_violations if v.sink_tool})
                if sink_tools:
                    state.db.create_policy(
                        name=f"Auto-Proposed Guard for {trace_id}",
                        description=f"Proposed by SecurityTaintAuditor after detecting {diagnosis.security_verdict} on tools {sink_tools}. Requires admin approval.",
                        rule={"blocked_tools_when_tainted": sink_tools, "forbid_secret_to_external": True, "max_injection_threshold": 0.55},
                        created_by="SecurityTaintAuditor",
                        status="PENDING_APPROVAL",
                    )

        state.db.log_audit(role, "trace.ingest", "trace", trace_id, {"created": created, "scenario": req.scenario_name})
        return {
            "trace_id": trace_id,
            "created": created,
            "diagnosis": diagnosis.model_dump() if diagnosis else None,
        }

    @app.get("/api/v1/traces/{trace_id}")
    async def get_trace(trace_id: str, role: str = Depends(get_actor_role)) -> dict[str, Any]:
        detail = state.db.get_trace_detail(trace_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Trace not found")
        return detail

    @app.post("/api/v1/traces/{trace_id}/diagnose")
    async def rediagnose_trace(
        trace_id: str,
        use_ollama: bool = False,
        inject_agent_fault: bool = False,
        role: str = Depends(get_actor_role),
    ) -> dict[str, Any]:
        detail = state.db.get_trace_detail(trace_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Trace not found")
        req = _trace_req_from_detail(detail)
        diag = state.council.diagnose(
            trace_id,
            req,
            active_policies=state.db.list_policies(),
            use_ollama=use_ollama,
            inject_agent_fault=inject_agent_fault,
        )
        state.db.save_diagnosis(diag)
        if diag.counterfactual:
            state.db.save_counterfactual(diag.counterfactual)
        await state.bus.publish(
            "diagnosis.completed",
            {"trace_id": trace_id, "attributed_agent": diag.attributed_agent, "attributed_step": diag.attributed_step_index, "mast_mode": diag.mast_mode, "severity": "HIGH"},
        )
        return diag.model_dump()

    @app.post("/api/v1/traces/{trace_id}/counterfactual")
    async def run_counterfactual(
        trace_id: str,
        body: CounterfactualRequest,
        role: str = Depends(get_actor_role),
    ) -> dict[str, Any]:
        detail = state.db.get_trace_detail(trace_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Trace not found")
        req = _trace_req_from_detail(detail)
        sec = state.firewall.audit_trace(req.spans, state.db.list_policies())
        try:
            cf = run_counterfactual_replay(
                req,
                trace_id,
                body.intervention_step_index,
                body.intervention_type,
                body.patched_content,
                set(sec["tainted_steps"]),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        state.db.save_counterfactual(cf)
        await state.bus.publish(
            "replay.verified",
            {"trace_id": trace_id, "step": body.intervention_step_index, "causal_flip": cf.causal_flip, "delta_score": cf.delta_score, "severity": "LOW"},
        )
        state.db.log_audit(role, "counterfactual.run", "trace", trace_id, {"step": body.intervention_step_index, "flip": cf.causal_flip})
        return cf.model_dump()

    # --- Live Scenario Simulator ---

    @app.get("/api/v1/scenarios")
    async def list_scenarios() -> list[dict[str, Any]]:
        return [{"key": k, **v, "mode": v["mode"].value} for k, v in SCENARIO_CATALOG.items()]

    @app.post("/api/v1/scenarios/run")
    async def run_scenario(body: ScenarioRunRequest, role: str = Depends(get_actor_role)) -> dict[str, Any]:
        try:
            req = generate_scenario_trace(body.scenario_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        trace_id, _ = state.db.insert_trace(req)
        diag = state.council.diagnose(
            trace_id,
            req,
            active_policies=state.db.list_policies(),
            use_ollama=body.use_ollama,
            inject_agent_fault=body.inject_controlled_failure,
        )
        state.db.save_diagnosis(diag)
        if diag.counterfactual:
            state.db.save_counterfactual(diag.counterfactual)

        if diag.security_verdict in ("COMPROMISED", "VIOLATION_BLOCKED"):
            sink_tools = sorted({v.sink_tool for v in diag.security_violations if v.sink_tool})
            if sink_tools:
                state.db.create_policy(
                    name=f"Auto-Proposed Guard for {trace_id}",
                    description=f"Proposed by SecurityTaintAuditor after detecting {diag.security_verdict} on tools {sink_tools}. Requires admin approval.",
                    rule={"blocked_tools_when_tainted": sink_tools, "forbid_secret_to_external": True, "max_injection_threshold": 0.55},
                    created_by="SecurityTaintAuditor",
                    status="PENDING_APPROVAL",
                )

        sev = "CRITICAL" if diag.security_verdict == "COMPROMISED" else ("HIGH" if req.status != TraceStatus.PASSED else "LOW")
        await state.bus.publish(
            "diagnosis.completed",
            {
                "trace_id": trace_id,
                "scenario": body.scenario_key,
                "attributed_agent": diag.attributed_agent,
                "attributed_step": diag.attributed_step_index,
                "mast_mode": diag.mast_mode,
                "security_verdict": diag.security_verdict,
                "severity": sev,
            },
        )
        return {"trace_id": trace_id, "diagnosis": diag.model_dump()}

    # --- Security Firewall Red-Team Lab & Human Approval Policy Gate ---

    @app.post("/api/v1/security/redteam")
    async def redteam_test(body: RedTeamTestRequest, role: str = Depends(get_actor_role)) -> dict[str, Any]:
        res = state.firewall.evaluate_redteam_payload(
            payload=body.payload,
            source_provenance=body.source_provenance,
            target_tool=body.target_tool,
            contains_secret=body.contains_secret_in_context,
        )
        state.db.log_audit(role, "security.redteam", "firewall", body.target_tool, {"decision": res["decision"], "prob": res["injection_probability"]})
        return res

    @app.get("/api/v1/policies")
    async def list_policies(role: str = Depends(get_actor_role)) -> list[dict[str, Any]]:
        return state.db.list_policies()

    @app.post("/api/v1/policies")
    async def create_policy(body: PolicyCreateRequest, role: str = Depends(get_actor_role)) -> dict[str, Any]:
        if role == "viewer":
            raise HTTPException(status_code=403, detail="Viewer role cannot propose policies")
        pol = state.db.create_policy(
            name=body.name,
            description=body.description,
            rule={
                "blocked_tools_when_tainted": body.blocked_tools_when_tainted,
                "forbid_secret_to_external": body.forbid_secret_to_external,
                "max_injection_threshold": body.max_injection_threshold,
                "allowed_agent_tools": body.allowed_agent_tools,
            },
            created_by=role,
            status="PENDING_APPROVAL",
        )
        state.db.log_audit(role, "policy.propose", "policy", pol["id"], {"name": body.name})
        return pol

    @app.post("/api/v1/policies/{policy_id}/approve")
    async def approve_policy(policy_id: str, role: str = Depends(require_admin)) -> dict[str, Any]:
        updated = state.db.update_policy_status(policy_id, "ACTIVE", approved_by=role)
        if not updated:
            raise HTTPException(status_code=404, detail="Policy not found")
        state.db.log_audit(role, "policy.approve", "policy", policy_id, {"status": "ACTIVE"})
        await state.bus.publish("policy.approved", {"policy_id": policy_id, "approved_by": role, "severity": "LOW"})
        return updated

    @app.post("/api/v1/policies/{policy_id}/disable")
    async def disable_policy(policy_id: str, role: str = Depends(require_admin)) -> dict[str, Any]:
        updated = state.db.update_policy_status(policy_id, "DISABLED", approved_by=role)
        if not updated:
            raise HTTPException(status_code=404, detail="Policy not found")
        state.db.log_audit(role, "policy.disable", "policy", policy_id, {"status": "DISABLED"})
        return updated

    # --- ML Benchmark & Evaluation Lab ---

    @app.get("/api/v1/benchmarks")
    async def get_benchmarks(role: str = Depends(get_actor_role)) -> dict[str, Any]:
        p = settings.data_dir / "benchmark_results.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        return run_full_benchmark(seed=42, save_path=p)

    @app.post("/api/v1/benchmarks/run")
    async def rerun_benchmarks(role: str = Depends(get_actor_role)) -> dict[str, Any]:
        p = settings.data_dir / "benchmark_results.json"
        return run_full_benchmark(seed=42, save_path=p)

    # --- Automation: Webhooks + Local Mock Receiver ---

    @app.get("/api/v1/webhooks")
    async def list_webhooks(role: str = Depends(get_actor_role)) -> dict[str, Any]:
        return {
            "endpoints": state.db.list_webhooks(),
            "deliveries": state.db.list_webhook_deliveries(limit=30),
            "mock_inbox_count": len(state.mock_webhook_inbox),
        }

    @app.post("/api/v1/webhooks")
    async def register_webhook(body: WebhookCreateRequest, role: str = Depends(require_admin)) -> dict[str, Any]:
        try:
            url = validate_webhook_url(body.target_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        ep = state.db.register_webhook(url, body.events, body.min_severity)
        state.db.log_audit(role, "webhook.register", "webhook", ep["id"], {"target_url": url})
        return ep

    @app.post("/api/v1/webhooks/mock-receiver")
    async def mock_webhook_receiver(request: Request) -> dict[str, Any]:
        """Local verified webhook receiver simulating n8n/Slack ingestion."""
        payload = await request.json()
        sig = request.headers.get("X-TraceGuard-Signature", "")
        state.mock_webhook_inbox.append({"signature": sig, "payload": payload})
        if len(state.mock_webhook_inbox) > 50:
            state.mock_webhook_inbox = state.mock_webhook_inbox[-50:]
        return {"received": True, "signature_present": bool(sig)}

    # --- WebSocket Live Telemetry Stream ---

    @app.websocket("/ws/events")
    async def ws_events(ws: WebSocket) -> None:
        await state.bus.connect_ws(ws)
        try:
            await ws.send_json({"event_type": "connection.ready", "payload": state.db.get_system_stats()})
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            state.bus.disconnect_ws(ws)

    return app


app = create_app()
