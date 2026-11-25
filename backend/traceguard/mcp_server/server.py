"""TraceGuard MCP Server — Exposes Causal Forensics, Counterfactual Replay & Firewall Tools via MCP."""
from __future__ import annotations

import json
from typing import Any

from traceguard.agents.council import DiagnosticCouncilSupervisor
from traceguard.core.counterfactual import run_counterfactual_replay
from traceguard.core.security_firewall import CapabilityFirewall
from traceguard.db.database import TraceGuardDB
from traceguard.schemas import ProvenanceLabel, SpanIn, TraceIngestRequest, TraceStatus


def _build_mcp_server():
    try:
        from mcp.server.mcpserver import MCPServer as ServerCls
    except ImportError:
        from mcp.server.fastmcp import FastMCP as ServerCls  # type: ignore[assignment]

    mcp = ServerCls("TraceGuard Forensic MCP")
    db = TraceGuardDB()
    firewall = CapabilityFirewall()
    council = DiagnosticCouncilSupervisor(firewall=firewall)

    @mcp.tool()
    def list_recent_traces(limit: int = 10) -> str:
        """List recent multi-agent OTel traces and their C3-Attributor diagnosis summaries."""
        return json.dumps(db.list_traces(limit=limit), indent=2)

    @mcp.tool()
    def inspect_trace_diagnosis(trace_id: str) -> str:
        """Retrieve full span waterfall, C3-Attributor root cause, security violations, and replays for a trace."""
        detail = db.get_trace_detail(trace_id)
        if not detail:
            return json.dumps({"error": f"Trace '{trace_id}' not found"})
        return json.dumps(detail, indent=2)

    @mcp.tool()
    def test_prompt_injection_firewall(
        payload: str,
        target_tool: str = "send_email",
        contains_secret: bool = True,
    ) -> str:
        """Evaluate an untrusted tool payload against TraceGuard's ML Injection Detector and CaMeL Capability Firewall."""
        res = firewall.evaluate_redteam_payload(
            payload=payload,
            source_provenance=ProvenanceLabel.UNTRUSTED_TOOL,
            target_tool=target_tool,
            contains_secret=contains_secret,
        )
        return json.dumps(res, indent=2)

    @mcp.tool()
    def run_trace_counterfactual(
        trace_id: str,
        intervention_step_index: int,
        intervention_type: str = "SANITIZE_TAINT",
    ) -> str:
        """Rewind a trace to intervention_step_index, apply a surgical patch, and verify if failure flips to RECOVERED."""
        detail = db.get_trace_detail(trace_id)
        if not detail:
            return json.dumps({"error": f"Trace '{trace_id}' not found"})
        t = detail["trace"]
        spans = [SpanIn(**{k: v for k, v in sp.items() if k in SpanIn.model_fields}) for sp in detail["spans"]]
        req = TraceIngestRequest(
            external_trace_id=t["external_trace_id"],
            scenario_name=t["scenario_name"],
            framework=t["framework"],
            status=TraceStatus(t["status"]),
            root_goal=t["root_goal"],
            spans=spans,
            auto_diagnose=False,
        )
        sec = firewall.audit_trace(spans, db.list_policies())
        cf = run_counterfactual_replay(req, trace_id, intervention_step_index, intervention_type, None, set(sec["tainted_steps"]))
        db.save_counterfactual(cf)
        return cf.model_dump_json(indent=2)

    return mcp


def main() -> None:
    mcp = _build_mcp_server()
    mcp.run()


if __name__ == "__main__":
    main()
