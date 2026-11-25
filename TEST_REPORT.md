# Verification & Test Report — TraceGuard

## 1. Automated Backend & ML Test Suite (`pytest`)
- **Command:** `cd backend && .venv/Scripts/python.exe -m pytest -v`
- **Result:** **15 passed, 0 failed, 0 errors** (14.96s on Windows / Python 3.12.9).

| Test Suite | Tests | Verified Behaviors |
|---|---:|---|
| `tests/test_ml_and_eval.py` | 4 | Family-disjoint `InjectBench-ToolIO` split; trace-disjoint `TraceBench-MAS` split; Injection ML F1 beats keyword baseline by >15 pts; C³-Attributor beats random, last-error, lexical-drift, and rule baselines with lower ECE. |
| `tests/test_security_and_cf.py` | 5 | CaMeL firewall blocks indirect exfiltration (`CAP-002-TAINTED-SINK-EXFILTRATION`); allows benign read tool; counterfactual replay flips on root cause and does NOT flip on healthy prefix; SSRF blocks `169.254.169.254`, `10.0.0.5`, `file://`; HMAC-SHA256 deterministic & tamper-sensitive. |
| `tests/test_council_and_api.py` | 6 | Health + idempotent trace ingestion deduplication; controlled `CounterfactualVerifierAgent` timeout -> graceful ML+Rule fallback + contradiction alert; RBAC (`401` invalid key, `403` viewer ingest, `403` analyst policy approve, `200` admin approve); malformed input `422` & out-of-bounds counterfactual `400`; unreachable webhook 3x retry -> `DEAD_LETTER`; MCP v2 server initialization. |

## 2. Frontend Build & Type Check
- **Command:** `cd frontend && npm run build` (`tsc && vite build`)
- **Result:** **Exit code 0** (0 TypeScript errors, 1,585 modules transformed, 274.96 kB JS bundle gzipped to 82.41 kB).

## 3. Flagship Demonstrations (A, B, C, D)
- **Command:** `cd backend && .venv/Scripts/python.exe scripts/run_demos.py`
- **Result:** **Exit code 0** — verified live execution of indirect prompt-injection forensics (Demo A), full benchmark table (Demo B), controlled agent timeout + webhook dead-letter recovery (Demo C), and red-team blocking + admin policy approval gate (Demo D).

## 4. Live Browser End-to-End Verification (`http://127.0.0.1:5173`)
Verified in a real Chromium browser at `1440x900` against the live FastAPI backend (`127.0.0.1:8000`):
- **Console errors:** `0` | **HTTP 4xx/5xx errors:** `0` across 50 requests.
- **Verified flows:** Seeded traces, 4-Agent Council strip, SVG Causal/Taint DAG, OTel Span Waterfall + Span Inspector, Counterfactual Replay (`BLOCK_UNAUTHORIZED_TOOL` non-flip vs `BREAK_LOOP` `FAILED → RECOVERED` flip), Red-Team Playground (`DECISION: BLOCK`, `p=99.1%`), ML Evaluation Lab tables, and Automation & Stream (mock webhook registration + live `Run Trace` -> WebSocket stream update + `DELIVERED (1x)` HMAC webhook delivery).

## 5. Defects Caught & Fixed During Testing
1. **MCP SDK v2 API Change:** `mcp==2.3.0` replaced `mcp.server.fastmcp.FastMCP` with `mcp.server.mcpserver.MCPServer`; updated `server.py` with dual v1/v2 compatibility.
2. **Windows SQLite File Handle Cleanup:** `sqlite3.Connection.__exit__` commits without closing handles; wrapped `_connect()` in `@contextmanager` with explicit `conn.close()` in `finally`.
3. **Scenario Runner Policy Gate Wiring:** Added `PENDING_APPROVAL` auto-proposal to `/api/v1/scenarios/run` to match `/api/v1/traces/ingest`.
4. **Browser UX Polish:** Fixed header `<select>` line-wrapping (`h-8 truncate`), SVG node ellipsis truncation, default recommended intervention selection in `CounterfactualLab`, intervention-specific replay notes, and singular/plural policy count.
