# Product Vision — TraceGuard

## 1. Product Identity
- **Name:** **TraceGuard**
- **Tagline:** *Causal Multi-Agent Failure Attribution, Prompt-Injection Capability Firewall & Counterfactual Replay Platform.*
- **Category:** AI Reliability, Agentic Observability & AI Security Infrastructure.

## 2. The Three Fundamental Questions

### 1) Why should this software exist?
When a multi-agent LLM system fails on step 14 of a 16-step tool-calling workflow—or silently leaks sensitive data after reading a poisoned document—standard observability dashboards only show a wall of nested JSON spans. Engineers waste hours manually reading agent transcripts to guess *which* agent made the decisive mistake and *whether* fixing that step actually resolves the failure. TraceGuard turns passive agent traces into **causally verified root-cause attributions**, **enforced capability security boundaries**, and **interactive time-travel counterfactual replays**.

### 2) Why is AI/ML necessary for this problem?
Deterministic rules alone catch obvious syntax or schema errors, but fail on subtle multi-agent failure modes (information withholding, semantic drift, hallucinated tool arguments, subtle indirect prompt injections embedded in retrieved web/email content). Conversely, pure LLM-as-a-judge fails on long traces (ICML 2025 *Who&When* showed frontier LLMs reach only 14.2% exact step localization). TraceGuard combines **trained ML classifiers** (character/word TF-IDF + calibrated Logistic/MLP prompt-injection detector; Gradient-Boosted/RandomForest step-fault ranker over 22 structural, graph, taint, and semantic features) with **symbolic constraint/taint tracking** and **deterministic counterfactual replay verification**—and empirically proves the gain over single-method baselines.

### 3) Why is this the right next step for Faris Ruknuddin's engineering profile?
Faris's audit (`PROFILE_AUDIT.md`) revealed strong FastAPI/TypeScript/testing skills, but two high-impact gaps: (a) lack of trained ML models with controlled baselines & ablations, and (b) zero public cybersecurity implementations despite listing cybersecurity as a core interest. TraceGuard directly converts both gaps into his strongest portfolio differentiator.

---

## 3. Target Audience & Alternatives
- **Target Users:** AI/ML Engineers building LangGraph/AutoGen/MCP agents; Platform/SRE teams operating production agents; AI Security Engineers red-teaming tool-using agents.
- **Existing Alternatives & Limitations:**
  - *Langfuse / Arize Phoenix / LangSmith:* Strong tracing & prompt-level evals, but no causal step-level failure localization (`who`/`when`), no CaMeL-style capability taint enforcement, and no counterfactual replay verifier.
  - *Lakera Guard / NeMo Guardrails:* Focus on text input/output filtering, not multi-step cross-agent data-flow taint or causal trace attribution.
  - *Academic Prototypes (AgenTracer, AgentRx, CaMeL):* Research scripts without OTel `gen_ai.*` ingestion, real-time operational UI, MCP tooling, or webhook/n8n incident automation.

---

## 4. Original Research & Engineering Contribution: **C³-Attributor**
**C³-Attributor (Causal–Constraint–Counterfactual Attribution Engine)**:
1. **Structural-Causal Trajectory Graph:** Parses OpenTelemetry `gen_ai.*` spans into a directed information-flow & data-dependency DAG tracking provenance (`TRUSTED_USER`, `UNTRUSTED_TOOL`, `SECRET_DATA`).
2. **Learned Step-Fault & Prompt-Injection Models:**
   - **Injection Detector:** Calibrated multi-feature TF-IDF (word + char n-grams) + Logistic Regression classifier trained on a curated, leakage-free stratified dataset of benign tool outputs vs. indirect prompt injections (override, exfiltration, tool-hijack, role-escalation).
   - **Step-Fault Ranker & MAST Classifier:** Trained Gradient Boosting / HistGradientBoosting ranker scoring each step across 22 engineered features (taint propagation, schema violation, semantic drift, loop repetition, context-drop, token anomaly, causal downstream fan-out, agent handoff delta) to predict `(responsible_agent, decisive_step, mast_failure_mode)`.
3. **Counterfactual Replay Verification:** Rewinds the trace to the top-$k$ attributed steps, injects a minimal surgical intervention (sanitize tainted tool output / restore withheld context / block unauthorized tool call), replays downstream deterministic state transitions, and computes a **Causal Verification Score** $\Delta_{\text{cf}} \in [0, 1]$ proving whether the intervention flips the outcome from `FAILED` to `RECOVERED`.

---

## 5. Measurable Success Criteria
- **ML Evaluation:** C³-Attributor beats all 4 baselines (Random, Last-Step Heuristic, Rule-Only MAST, Embedding-Drift Only) on **Top-1 Step Localization Accuracy**, **Top-3 Step Accuracy**, **Agent Attribution Accuracy**, and **Injection Detection F1 / ROC-AUC**, with full ablation table and ECE calibration.
- **End-to-End Flow:** Single ingested OTel trace triggers: `Ingestion → 4-Agent Diagnostic Council → C³ Attribution → Counterfactual Verification → SQLite WAL Persistence → WebSocket Broadcast → Webhook/n8n Alert Dispatch → Interactive UI Inspection`.
- **Verification:** Comprehensive automated backend, ML, security, failure-recovery, and browser UI tests passing with zero fabricated results.

## 6. Project Boundaries & Non-Goals
- **Non-Goals:** Not a cloud-hosted SaaS billing platform; not a replacement for generic APM (CPU/memory profiling); does not claim zero-day immunity against adaptive white-box LLM jailbreaks.
- **Local-First Reproducibility:** Works 100% offline with local scikit-learn models, SQLite WAL, and optional local Ollama (`llama3.2:3b`) integration—no paid cloud API keys required.
