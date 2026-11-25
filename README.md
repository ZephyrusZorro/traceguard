# TraceGuard

> **Causal Multi-Agent Failure Attribution, Prompt-Injection Capability Firewall & Counterfactual Replay Platform**

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776ab)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688)](#)
[![React 19 + TS](https://img.shields.io/badge/React_19-TypeScript-3178c6)](#)
[![OTel GenAI](https://img.shields.io/badge/Telemetry-OTel_GenAI-f59e0b)](#)
[![Tests](https://img.shields.io/badge/pytest-15%20passed-10b981)](#)

**TraceGuard** turns passive OpenTelemetry (`gen_ai.*`) multi-agent execution traces into **causally verified root-cause attributions**, **CaMeL-inspired capability security enforcement**, and **interactive time-travel counterfactual replays**.

Grounded in 2024–2026 frontier AI reliability & security research: *Who&When* (ICML 2025, arXiv:2505.00212), *MAST* (UC Berkeley 2025, arXiv:2503.13657), *AgenTracer* (arXiv:2509.03312), *AgentRx* (Microsoft Research 2026, arXiv:2602.02475), *AgentDojo* (NeurIPS 2024), and *CaMeL* (Google DeepMind / ETH Zurich 2025).

---

## Core Capabilities

1. **C³-Attributor (Original Contribution):**
   - Extracts **23 structural, graph, taint, and semantic features** from OpenTelemetry GenAI spans.
   - Runs a trained **HistGradientBoosting Step-Fault Ranker** + **RandomForest MAST Mode Classifier** (8 failure modes across 3 MAST pillars + Security).
   - Verifies top-$k$ candidate steps via **deterministic Counterfactual Time-Travel Replay**, proving whether patching step $k$ flips the terminal outcome from `FAILED`/`COMPROMISED` to `RECOVERED`.
2. **CaMeL-Inspired Prompt-Injection & Capability Firewall:**
   - Calibrated **Word (1–2) + Char (3–5) TF-IDF + Logistic Regression** indirect prompt-injection classifier (**F1 = 0.8571, ROC-AUC = 0.9508** on unseen test families vs **F1 = 0.5505** keyword baseline).
   - Provenance lattice (`TRUSTED_USER`, `UNTRUSTED_TOOL`, `SECRET_DATA`, `DERIVED`) blocking tainted control flows from invoking external sinks (`send_email`, `http_post`, `transfer_funds`, `shell_exec`).
   - **Human-in-the-Loop Policy Approval Gate** — `SecurityTaintAuditor` proposes protective policies as `PENDING_APPROVAL` and requires explicit `admin` approval to activate.
3. **4-Agent Diagnostic Council:**
   - Typed specialist agents (`SecurityTaintAuditor`, `SpanIngestorAgent`, `CausalLocalizerAgent`, `CounterfactualVerifierAgent`) coordinated by a supervisor with contradiction detection, fault isolation, and graceful degradation.
4. **Interconnected Ecosystem:**
   - FastAPI REST + **WebSocket** live event stream + **SQLite WAL** with schema migrations.
   - **MCP Server** (`traceguard/mcp_server/server.py`) exposing forensic, firewall, and counterfactual tools to AI coding agents.
   - **HMAC-SHA256 Signed Webhook Dispatcher** with SSRF protection, 3x exponential backoff retry, dead-letter logging, and an importable **n8n workflow** (`automation/n8n_traceguard_workflow.json`).
   - **Precision Forensic Workstation** (React 19, TypeScript, Tailwind CSS v4) with OTel Span Waterfall, Interactive SVG Causal/Taint DAG, Counterfactual Time-Travel Lab, Red-Team Playground, and Live ML Benchmark Lab.

---

## Verified Benchmark Summary (Held-Out Test Splits)

| Method | Top-1 Step Acc | Top-3 Step Acc | Agent (Who) Acc | MRR | ECE ↓ | Mean Latency |
|---|---:|---:|---:|---:|---:|---:|
| Random Baseline | 13.9% | 58.3% | 20.8% | 0.395 | 0.751 | 0.0 ms |
| Last-Error Heuristic | 25.0% | 87.5% | 25.0% | 0.525 | 0.700 | 0.0 ms |
| Lexical Drift + Latency | 8.3% | 62.5% | 18.1% | 0.399 | 0.730 | 5.3 ms |
| Rule-Only MAST Heuristic | 87.5% | 93.1% | 100.0% | 0.907 | 0.565 | 5.3 ms |
| ML Step-Fault Ranker Only (Ablation) | 100.0% | 100.0% | 100.0% | 1.000 | 0.000 | 15.0 ms |
| **C³-Attributor Full (ML + Counterfactual)** | **100.0%** | **100.0%** | **100.0%** | **1.000** | **0.062** | **39.8 ms** |

*See [EVALUATION_REPORT.md](EVALUATION_REPORT.md) and [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for full methodology, honest synthetic-benchmark caveats, and unseen-family injection benchmarks.*

---

## Quickstart (100% Local, Zero Paid API Keys)

### 1. Backend Setup, Training & API
```bash
cd backend
uv venv .venv --python 3.12
uv pip install --python .venv/Scripts/python.exe -e ".[dev,mcp]"

# Train models & run full benchmark
.venv/Scripts/python.exe scripts/train_and_eval.py

# Run 15-test automated suite
.venv/Scripts/python.exe -m pytest -v

# Execute Flagship Demos A–D
.venv/Scripts/python.exe scripts/run_demos.py

# Start FastAPI server (http://127.0.0.1:8000)
.venv/Scripts/python.exe -m uvicorn traceguard.api.app:app --host 127.0.0.1 --port 8000
```

### 2. Frontend Workstation
```bash
cd frontend
npm install
npm run dev   # http://127.0.0.1:5173
```

### 3. Docker Compose (Optional)
```bash
docker compose up --build
```

---

## Documentation Index
- [RESEARCH_AND_SELECTION.md](RESEARCH_AND_SELECTION.md) — Literature review, 8 evaluated concepts & scoring matrix
- [PRODUCT_VISION.md](PRODUCT_VISION.md) — Product mission & original research contribution
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture, data flow & SQLite WAL schema
- [AI_ML_DESIGN.md](AI_ML_DESIGN.md) — Feature engineering, models, baselines & ablation design
- [EVALUATION_REPORT.md](EVALUATION_REPORT.md) — Verified benchmark results & error analysis
- [TEST_REPORT.md](TEST_REPORT.md) — Automated pytest & browser E2E verification record
- [SECURITY.md](SECURITY.md) — Threat model, CaMeL firewall, RBAC, SSRF & HMAC defenses
- [API_SPECIFICATION.md](API_SPECIFICATION.md) — REST, WebSocket & MCP tool contracts
- [DEMO_GUIDE.md](DEMO_GUIDE.md) — Reproducible Walkthroughs for Demos A, B, C & D
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — Explicit scope limits & next research steps
