"""Structural Causal & Provenance Dependency Graph Builder (NetworkX)."""
from __future__ import annotations

from typing import Any
import networkx as nx

from traceguard.schemas import ProvenanceLabel, SpanIn


def build_causal_graph(
    spans: list[SpanIn],
    injection_probs: list[float] | None = None,
    tainted_steps: set[int] | None = None,
) -> tuple[nx.DiGraph, dict[str, Any]]:
    """Construct a directed execution & information-flow DAG from OTel GenAI spans."""
    g = nx.DiGraph()
    ordered = sorted(spans, key=lambda s: s.step_index)
    tainted_steps = tainted_steps or set()
    inj_map = {s.step_index: (injection_probs[i] if injection_probs and i < len(injection_probs) else 0.0) for i, s in enumerate(ordered)}

    id_to_step: dict[str, int] = {}
    for s in ordered:
        id_to_step[s.span_id] = s.step_index
        g.add_node(
            s.step_index,
            span_id=s.span_id,
            agent=s.agent_name,
            operation=s.operation_name,
            tool=s.tool_name,
            status=s.status,
            provenance=s.provenance.value,
            tainted=s.step_index in tainted_steps,
            injection_prob=inj_map[s.step_index],
            latency_ms=s.latency_ms,
        )

    # 1. Explicit parent_span_id edges (control flow)
    for idx, s in enumerate(ordered):
        if s.parent_span_id and s.parent_span_id in id_to_step:
            src = id_to_step[s.parent_span_id]
            if src != s.step_index:
                g.add_edge(src, s.step_index, edge_type="control_flow")
        elif idx > 0:
            g.add_edge(ordered[idx - 1].step_index, s.step_index, edge_type="sequential")

        # 2. Explicit taint/data-flow edges (e.g., taint_consumed_from)
        taint_src_id = s.attributes.get("taint_consumed_from")
        if taint_src_id and taint_src_id in id_to_step:
            src = id_to_step[taint_src_id]
            if src != s.step_index:
                g.add_edge(src, s.step_index, edge_type="taint_flow")

    # 3. Secret-data flow edges (any downstream external sink after a SECRET_DATA span)
    secret_steps = [s.step_index for s in ordered if s.provenance == ProvenanceLabel.SECRET_DATA]
    for s in ordered:
        if s.attributes.get("external_sink") or s.attributes.get("contains_secret"):
            for sec_step in secret_steps:
                if sec_step < s.step_index and not g.has_edge(sec_step, s.step_index):
                    g.add_edge(sec_step, s.step_index, edge_type="secret_flow")

    # Compute structural metrics
    cycles = list(nx.simple_cycles(g))
    orphan_spans = [
        s.step_index for s in ordered
        if s.step_index > 0 and g.in_degree(s.step_index) == 0
    ]
    downstream_errors: dict[int, int] = {}
    for s in ordered:
        desc = nx.descendants(g, s.step_index)
        downstream_errors[s.step_index] = sum(
            1 for d in desc if g.nodes[d]["status"] in ("ERROR", "WARNING", "BLOCKED")
        )

    serializable = {
        "nodes": [
            {"id": n, **g.nodes[n], "downstream_errors": downstream_errors.get(n, 0)}
            for n in g.nodes
        ],
        "edges": [
            {"source": u, "target": v, **data}
            for u, v, data in g.edges(data=True)
        ],
        "metrics": {
            "node_count": g.number_of_nodes(),
            "edge_count": g.number_of_edges(),
            "has_cycles": len(cycles) > 0,
            "orphan_spans": orphan_spans,
            "downstream_errors": downstream_errors,
        },
    }
    return g, serializable
