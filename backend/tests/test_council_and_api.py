"""API Contract, RBAC Security, 4-Agent Council Fault Recovery, Idempotency & MCP Tests."""
from __future__ import annotations

from pathlib import Path
from fastapi.testclient import TestClient

from traceguard.api.app import create_app
from traceguard.config import settings
from traceguard.core.simulator import generate_scenario_trace
from traceguard.mcp_server.server import _build_mcp_server


def _client(tmp_path: Path) -> TestClient:
    app = create_app(db_path=tmp_path / "test_tg.db", seed_initial=False)
    return TestClient(app)


def test_health_and_idempotent_ingest_and_council_diagnosis(tmp_path: Path):
    with _client(tmp_path) as client:
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["models_loaded"] is True

        req = generate_scenario_trace("devops_info_withholding", seed=12)
        payload = req.model_dump()
        r1 = client.post("/api/v1/traces/ingest", json=payload)
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["created"] is True
        assert d1["diagnosis"]["attributed_step_index"] == req.ground_truth_step
        assert d1["diagnosis"]["attributed_agent"] == req.ground_truth_agent
        assert len(d1["diagnosis"]["agent_reports"]) == 4

        # Duplicate idempotency_key must NOT create a second trace row
        r2 = client.post("/api/v1/traces/ingest", json=payload)
        assert r2.status_code == 200
        assert r2.json()["created"] is False
        assert r2.json()["trace_id"] == d1["trace_id"]


def test_controlled_agent_failure_graceful_degradation(tmp_path: Path):
    with _client(tmp_path) as client:
        r = client.post(
            "/api/v1/scenarios/run",
            json={"scenario_key": "support_tool_hallucination", "inject_controlled_failure": True},
        )
        assert r.status_code == 200
        diag = r.json()["diagnosis"]
        cf_agent = next(a for a in diag["agent_reports"] if a["agent_name"] == "CounterfactualVerifierAgent")
        assert cf_agent["status"] == "TIMEOUT"
        assert diag["contradiction_detected"] is True
        assert "degraded" in (diag["contradiction_note"] or "").lower()
        # Fallback ML+Rule attribution still succeeds
        assert diag["attributed_agent"] != "NONE"


def test_rbac_enforcement_on_admin_and_viewer_routes(tmp_path: Path):
    with _client(tmp_path) as client:
        # Invalid key -> 401
        r_bad = client.get("/api/v1/traces", headers={"X-API-Key": "wrong-key"})
        assert r_bad.status_code == 401

        # Viewer cannot ingest -> 403
        req = generate_scenario_trace("healthy_baseline", seed=5).model_dump()
        r_view = client.post("/api/v1/traces/ingest", json=req, headers={"X-API-Key": settings.viewer_api_key})
        assert r_view.status_code == 403

        # Analyst can propose policy, but CANNOT approve it (Human Approval Gate requires admin)
        pol = client.post(
            "/api/v1/policies",
            json={"name": "Block Shell", "description": "Disallow shell_exec when tainted", "blocked_tools_when_tainted": ["shell_exec"]},
            headers={"X-API-Key": settings.analyst_api_key},
        )
        assert pol.status_code == 200
        pid = pol.json()["id"]
        assert pol.json()["status"] == "PENDING_APPROVAL"

        r_forbid = client.post(f"/api/v1/policies/{pid}/approve", headers={"X-API-Key": settings.analyst_api_key})
        assert r_forbid.status_code == 403

        r_ok = client.post(f"/api/v1/policies/{pid}/approve", headers={"X-API-Key": settings.admin_api_key})
        assert r_ok.status_code == 200
        assert r_ok.json()["status"] == "ACTIVE"


def test_adversarial_malformed_inputs_and_out_of_bounds_counterfactual(tmp_path: Path):
    with _client(tmp_path) as client:
        # Empty spans rejected by Pydantic
        r_empty = client.post(
            "/api/v1/traces/ingest",
            json={"external_trace_id": "bad", "root_goal": "x", "spans": []},
        )
        assert r_empty.status_code == 422

        # Out-of-bounds counterfactual step -> 400
        r_run = client.post("/api/v1/scenarios/run", json={"scenario_key": "fin_infinite_loop"})
        tid = r_run.json()["trace_id"]
        r_oob = client.post(
            f"/api/v1/traces/{tid}/counterfactual",
            json={"intervention_step_index": 999, "intervention_type": "BREAK_LOOP"},
        )
        assert r_oob.status_code == 400


def test_webhook_dead_letter_on_unreachable_endpoint(tmp_path: Path):
    with _client(tmp_path) as client:
        # Register an unreachable local port to verify retry + DEAD_LETTER recording
        r_wh = client.post(
            "/api/v1/webhooks",
            json={"target_url": "http://127.0.0.1:59999/dead-endpoint", "events": ["diagnosis.completed"], "min_severity": "HIGH"},
            headers={"X-API-Key": settings.admin_api_key},
        )
        assert r_wh.status_code == 200

        client.post("/api/v1/scenarios/run", json={"scenario_key": "ebanking_prompt_injection"})
        wh_list = client.get("/api/v1/webhooks").json()
        assert len(wh_list["deliveries"]) >= 1
        assert wh_list["deliveries"][0]["status"] == "DEAD_LETTER"
        assert wh_list["deliveries"][0]["attempts"] == 3


def test_mcp_server_initializes_with_forensic_tools():
    mcp = _build_mcp_server()
    assert mcp is not None
    assert mcp.name == "TraceGuard Forensic MCP"
