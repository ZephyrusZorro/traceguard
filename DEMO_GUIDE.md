# Flagship Demonstration Guide — TraceGuard

All four flagship demonstrations execute against the real FastAPI + ML + SQLite + Automation engine with zero mocked analytics.

**Automated CLI Runner:**
```bash
cd backend
.venv/Scripts/python.exe scripts/run_demos.py
```

---

## Demo A — Complete Product Workflow (Indirect Prompt Injection Forensics)
1. **Trigger:** Run `ebanking_prompt_injection` via CLI or the UI header (**Run Trace**).
2. **Flow:** `Scenario Runner → SQLite WAL Ingest → 4-Agent Diagnostic Council (SecurityTaintAuditor → SpanIngestorAgent → CausalLocalizerAgent → CounterfactualVerifierAgent) → WebSocket Broadcast → Policy Gate Proposal`.
3. **Verified Output:**
   - Attributed Root Cause: `PaymentExecutorAgent` @ Step `#4` (`SEC_INDIRECT_PROMPT_INJECTION`, `COMPROMISED`).
   - Counterfactual Verification: `BLOCK_UNAUTHORIZED_TOOL` flips terminal outcome `COMPROMISED → RECOVERED` (`Δ = 0.84`, 2 downstream steps recovered).
   - Interactive UI: Inspect crimson dashed `taint_flow` edge in the Causal DAG and C³ attribution heatmap in the OTel Span Waterfall.

## Demo B — Advanced AI/ML Capability & Comparative Benchmark
1. **Trigger:** Open **ML Evaluation Lab** tab (or run `scripts/train_and_eval.py`).
2. **Verified Output:**
   - **Step Attribution (n=72 held-out test traces):** `C³-Attributor` (`100.0%` Top-1, `ECE=0.062`, `39.8 ms`) vs `Rule-Only MAST` (`87.5%`, `ECE=0.565`), `Last-Error` (`25.0%`), `Random` (`13.9%`), `Lexical Drift` (`8.3%`).
   - **Indirect Prompt-Injection (unseen test families):** Calibrated Word+Char TF-IDF + LogReg (`F1=0.8571`, `ROC-AUC=0.9508`, `Recall=95.0%`) vs Keyword Baseline (`F1=0.5505`, `Recall=50.0%`).

## Demo C — Interconnected Systems & Controlled Failure Recovery
1. **Trigger:** Check **Fault-Inject** in the top header and run `devops_info_withholding`, while an unreachable webhook endpoint is registered.
2. **Verified Behavior:**
   - `CounterfactualVerifierAgent` reports `TIMEOUT`.
   - Supervisor raises a visible **Contradiction / Degradation Alert** and seamlessly falls back to calibrated ML+Rule ranking, still attributing `RootCauseAnalyst` (`MISALIGN_INFO_WITHHOLDING`).
   - Outbound webhook dispatcher executes **3 exponential-backoff retries** and records `DEAD_LETTER` in `webhook_deliveries` without blocking the API response.

## Demo D — Capability Firewall Red-Team & Human Approval Gate
1. **Trigger:** Open **Capability Firewall** tab, evaluate the indirect exfiltration payload (`send_email` + `SECRET_DATA`), then click **Approve** on the auto-proposed pending policy.
2. **Verified Behavior:**
   - Firewall returns `DECISION: BLOCK` (`p=0.913`–`0.991`, `CAP-002-TAINTED-SINK-EXFILTRATION`).
   - Policy transitions `PENDING_APPROVAL → ACTIVE` only with `admin` API key (`analyst` receives `403 Forbidden`), logged in `audit_logs`.
