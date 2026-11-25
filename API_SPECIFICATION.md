# API & MCP Specification — TraceGuard v1.0

**Base URL:** `http://127.0.0.1:8000`  
**Auth Header:** `X-API-Key: <key>` or `Authorization: Bearer <key>` (`admin`, `analyst`, `viewer` roles).

## 1. REST Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | Public | Service health, model load status, and SQLite system stats. |
| `GET` | `/api/v1/traces` | Any | List ingested OTel GenAI traces with latest C³-Attributor diagnosis summary. |
| `POST` | `/api/v1/traces/ingest` | Analyst/Admin | Idempotently ingest an OTel trace (`idempotency_key`), optionally trigger 4-Agent Council. |
| `GET` | `/api/v1/traces/{trace_id}` | Any | Retrieve full trace, spans, latest diagnosis, causal graph, and counterfactual replays. |
| `POST` | `/api/v1/traces/{trace_id}/diagnose` | Analyst/Admin | Re-run 4-Agent Council (`?use_ollama=bool&inject_agent_fault=bool`). |
| `POST` | `/api/v1/traces/{trace_id}/counterfactual` | Analyst/Admin | Rewind trace to `intervention_step_index`, apply patch, and verify causal recovery. |
| `GET` | `/api/v1/scenarios` | Public | List 8 built-in multi-agent failure & baseline scenarios. |
| `POST` | `/api/v1/scenarios/run` | Analyst/Admin | Generate, ingest, and diagnose a live multi-agent scenario trace. |
| `POST` | `/api/v1/security/redteam` | Analyst/Admin | Evaluate an untrusted payload against ML Injection Detector + CaMeL Capability Firewall. |
| `GET` | `/api/v1/policies` | Any | List capability firewall policies (`ACTIVE`, `PENDING_APPROVAL`, `DISABLED`). |
| `POST` | `/api/v1/policies` | Analyst/Admin | Propose a new capability policy (queued as `PENDING_APPROVAL`). |
| `POST` | `/api/v1/policies/{id}/approve` | **Admin** | Approve and activate a pending capability policy (Human Approval Gate). |
| `POST` | `/api/v1/policies/{id}/disable` | **Admin** | Disable an active capability policy. |
| `GET` | `/api/v1/benchmarks` | Any | Return persisted ML evaluation & ablation benchmark results. |
| `POST` | `/api/v1/benchmarks/run` | Analyst/Admin | Re-train models and execute live benchmark suite. |
| `GET` | `/api/v1/webhooks` | Any | List registered webhook endpoints, delivery logs, and mock inbox count. |
| `POST` | `/api/v1/webhooks` | **Admin** | Register an SSRF-validated webhook endpoint for HMAC-signed alerts. |
| `POST` | `/api/v1/webhooks/mock-receiver` | Public | Local verified webhook sink simulating n8n/Slack ingestion. |
| `GET` | `/api/v1/events/recent` | Any | Recent Event Bus envelopes. |
| `GET` | `/api/v1/audit-logs` | Any | Immutable security & operator audit trail. |

## 2. WebSocket Stream
- `WS /ws/events` — Pushes real-time JSON envelopes (`trace.ingested`, `diagnosis.completed`, `security.alert`, `replay.verified`, `policy.approved`).

## 3. MCP Server Tools (`backend/traceguard/mcp_server/server.py`)
- `list_recent_traces(limit=10)`
- `inspect_trace_diagnosis(trace_id)`
- `test_prompt_injection_firewall(payload, target_tool="send_email", contains_secret=True)`
- `run_trace_counterfactual(trace_id, intervention_step_index, intervention_type="SANITIZE_TAINT")`
