# Implementation Plan & Architecture Decisions — TraceGuard

## 1. Repository Layout

```text
traceguard/
├── backend/
│   ├── pyproject.toml
│   ├── traceguard/
│   │   ├── __init__.py
│   │   ├── config.py                  # Centralized Pydantic settings
│   │   ├── schemas.py                 # Typed API, OTel span, Agent & Policy contracts
│   │   ├── db/
│   │   │   ├── database.py            # SQLite WAL connection, migrations, repositories
│   │   ├── ml/
│   │   │   ├── dataset.py             # Reproducible TraceBench-MAS & InjectBench-ToolIO generators
│   │   │   ├── features.py            # 22-feature causal/structural span extractor
│   │   │   ├── injection_model.py     # Calibrated Word+Char TF-IDF + LogReg injection detector
│   │   │   ├── attribution_model.py   # HistGradientBoosting Step-Fault Ranker + MAST Classifier
│   │   │   └── evaluation.py          # Full benchmark runner (6 methods + ablations + ECE)
│   │   ├── core/
│   │   │   ├── causal_graph.py        # NetworkX execution & provenance DAG builder
│   │   │   ├── security_firewall.py   # CaMeL-inspired taint lattice & capability policy engine
│   │   │   ├── counterfactual.py      # Deterministic time-travel counterfactual replay engine
│   │   │   └── simulator.py           # Live multi-agent scenario runner (deterministic + Ollama)
│   │   ├── agents/
│   │   │   └── council.py             # 4-Agent Diagnostic Council + Supervisor + Contradiction Detector
│   │   ├── automation/
│   │   │   ├── event_bus.py           # Async pub/sub + WebSocket broadcast manager
│   │   │   └── webhooks.py            # HMAC-SHA256 webhook dispatcher + retry + n8n workflow export
│   │   ├── mcp_server/
│   │   │   └── server.py              # MCP-compatible server exposing forensic tools
│   │   └── api/
│   │       ├── app.py                 # FastAPI app, RBAC auth, rate limiter, REST + WS routes
│   ├── scripts/
│   │   ├── train_and_eval.py          # Reproducible training + benchmark + artifact export
│   │   └── run_demos.py               # Automated execution of Demos A, B, C, D
│   └── tests/
│       ├── test_ml_and_eval.py        # ML models, leakage-free split, benchmark assertions
│       ├── test_security_and_cf.py    # CaMeL firewall, injection red-team, counterfactual flip
│       ├── test_council_and_api.py    # 4-agent council, API contracts, auth, idempotency, failure recovery
│       └── test_adversarial.py        # Malformed payloads, SSRF, SQLi/prompt-injection, concurrency
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx                    # Precision Forensic Workstation (5 operational views)
│       ├── api.ts                     # Typed API client + WebSocket hook
│       ├── types.ts
│       └── components/
│           ├── TraceWaterfall.tsx     # OTel span timeline + attribution heatmap
│           ├── CausalGraphView.tsx    # Interactive SVG causal & taint dependency DAG
│           ├── CounterfactualLab.tsx  # Time-travel intervention editor & diff viewer
│           ├── SecurityFirewall.tsx   # Live red-team playground + policy approval gate
│           └── BenchmarkLab.tsx       # Live ML evaluation, baselines & ablation charts
├── automation/
│   └── n8n_traceguard_workflow.json   # Importable n8n incident triage & alert workflow
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── .github/workflows/ci.yml
└── [Project Documentation Suite]
```

## 2. Key Architecture Decision Records (Summary)

| ADR | Decision | Rationale | Rejected Alternative |
|---|---|---|---|
| **ADR-01** | **Python 3.12 + FastAPI + scikit-learn + NetworkX** for backend & ML | Fast CPU training/inference (<30 ms/trace), zero GPU requirement for evaluators, strong typing with Pydantic v2, aligns with Faris's core stack while introducing real ML engineering. | Heavy PyTorch/LLM-fine-tuning stack (too slow to reproduce on arbitrary evaluator laptops without GPU). |
| **ADR-02** | **SQLite WAL with explicit schema migrations** (PostgreSQL-compatible SQL) | Zero-daemon local reproducibility (Docker Desktop is offline on host), atomic transactions, WAL concurrent reads, instant test isolation. | Requiring external Postgres + Kafka daemons just to boot local dev. |
| **ADR-03** | **Hybrid C³-Attributor (ML + Symbolic Taint + Counterfactual Replay)** | Pure LLM-as-a-judge gets 14.2% step accuracy (*Who&When*); pure heuristics miss paraphrased injections & cascading failures. Hybrid provides calibrated scores + causal proof. | Pure LLM prompt wrapper or pure regex rules. |
| **ADR-04** | **Deterministic Counterfactual Replay + Optional Ollama Narrative** | Ensures 100% reproducible causal verification and fast unit/CI tests even when Ollama is offline, while leveraging local `llama3.2:3b` when available for operator summaries. | Hard dependency on cloud OpenAI/Anthropic API keys. |
| **ADR-05** | **React 19 + TypeScript + Vite + Tailwind CSS v4** | Clean SPA with zero SSR complexity, fast builds, crisp Linear/Sentry-inspired obsidian-slate forensic UI. | Streamlit (insufficient layout precision for span waterfalls and interactive DAGs). |
