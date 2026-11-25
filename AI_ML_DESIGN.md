# AI/ML Research Design & Evaluation Methodology — TraceGuard

## 1. Research Questions & Hypotheses
- **RQ1 (Step-Level Failure Attribution):** Can a lightweight hybrid neuro-symbolic model (**C³-Attributor**: engineered structural/taint/graph/semantic features + trained Gradient-Boosted Ranker + deterministic Counterfactual Replay verification) significantly outperform heuristic, rule-only, and embedding-drift baselines on multi-agent failure attribution (`Who` agent and `When` exact step)?
- **RQ2 (Indirect Prompt-Injection & Exfiltration Defense):** Does combining a calibrated TF-IDF + Logistic Regression injection detector with a CaMeL-inspired Information-Flow & Capability Policy Engine reduce false negatives and false positives compared to keyword/regex heuristics or text-only classifiers?
- **Hypothesis:** Combining learned step-level risk scoring with causal counterfactual replay verification improves Top-1 exact step localization by $\ge 20$ percentage points over passive heuristic/drift baselines while keeping inference latency under 30 ms per trace on CPU.

---

## 2. Reproducible Benchmark Datasets (Zero Data Leakage)

All datasets are generated deterministically from versioned seeds (`seed=42`) with **strict trace-level / group-level train-validation-test splitting** (no trace or template family leaks between train and test splits):

### Dataset A: Multi-Agent Failure Attribution Corpus (`TraceBench-MAS`, 360 Traces / ~3,900 Spans)
- Aligned with **Who&When** (ICML 2025) and **MAST** (UC Berkeley 2025) schemas.
- Covers **5 realistic multi-agent workflow topologies** (Enterprise Support Ops, Financial Research Desk, DevOps Incident Response, E-Banking Assistant, Code Review Pipeline) across **4–6 distinct agents per topology**.
- Covers **8 canonical failure modes** across all 3 MAST pillars + Security:
  1. `SPEC_ROLE_VIOLATION` (Pillar 1: System Design)
  2. `SPEC_INFINITE_LOOP` (Pillar 1: System Design)
  3. `SPEC_CONTEXT_RESET` (Pillar 1: System Design)
  4. `MISALIGN_INFO_WITHHOLDING` (Pillar 2: Inter-Agent Misalignment)
  5. `MISALIGN_TOOL_ARG_HALLUCINATION` (Pillar 2: Inter-Agent Misalignment)
  6. `VERIFY_PREMATURE_TERMINATION` (Pillar 3: Verification & Termination)
  7. `VERIFY_SUPERFICIAL_CHECK` (Pillar 3: Verification & Termination)
  8. `SEC_INDIRECT_PROMPT_INJECTION` (Security: AgentDojo / CaMeL Exfiltration)
- Every failing trace has ground-truth `(root_agent, decisive_step_index, mast_mode)` AND realistic **downstream cascading noise** (subsequent agents fail *because* of the earlier error, making naive "last-step" attribution fail—just as in real multi-agent logs).
- **Split:** 216 train traces / 72 validation traces / 72 held-out test traces (stratified by failure mode & topology, with unseen prompt paraphrases and unseen entity names in the test split).

### Dataset B: Indirect Prompt-Injection Corpus (`InjectBench-ToolIO`, 600 Tool Payloads)
- Stratified binary + multi-category corpus of tool outputs (emails, web pages, SQL rows, API JSON, support tickets) split 60/20/20 by template family so the test set evaluates **generalization to unseen phrasing**.
- Categories: `BENIGN`, `INSTRUCTION_OVERRIDE`, `DATA_EXFILTRATION`, `TOOL_HIJACK`, `PRIVILEGE_ESCALATION`, plus **hard negatives** (benign security documentation or support tickets mentioning words like "ignore", "system", "password" without malicious intent).

---

## 3. Feature Engineering (22 Per-Step Causal & Structural Features)

For every span $s_i$ in a trace $T = (s_0, \dots, s_{n-1})$, `FeatureExtractor` computes a deterministic 22-dimensional vector:
1. `rel_position`: $i / \max(1, n-1)$
2. `is_first_step`, `is_last_step`
3. `op_is_tool`, `op_is_chat`, `op_is_agent`
4. `status_error`: whether span exited with error/timeout
5. `latency_zscore`: standardized latency vs trace mean
6. `token_ratio`: `tokens_out / max(1, tokens_in)`
7. `token_drop_flag`: sharp context drop relative to prior span (captures `SPEC_CONTEXT_RESET`)
8. `jaccard_prev_output`: lexical overlap with prior span output (captures `SPEC_INFINITE_LOOP`)
9. `repeat_agent_tool_count`: repeated `(agent, tool)` invocations in sliding window
10. `goal_lexical_overlap`: relevance of step output to `root_goal`
11. `info_entropy_delta`: key-entity retention ratio between input and output (captures `MISALIGN_INFO_WITHHOLDING`)
12. `schema_violation_flag`: malformed or out-of-contract tool arguments (captures `MISALIGN_TOOL_ARG_HALLUCINATION`)
13. `role_violation_flag`: agent invokes tool outside its declared capability allowlist (captures `SPEC_ROLE_VIOLATION`)
14. `taint_introduced`: span reads `UNTRUSTED_TOOL` and triggers injection score > 0.35
15. `taint_propagated`: span consumes tainted ancestor data
16. `capability_policy_violation`: CaMeL taint-to-sink violation (e.g., `SECRET_DATA` + tainted flow → external sink)
17. `injection_ml_prob`: calibrated probability from Dataset B's trained Injection Classifier
18. `downstream_error_fanout`: number of subsequent spans in the causal DAG with errors or degraded goal alignment
19. `verifier_skip_flag`: verifier/reviewer agent emits `APPROVED` despite upstream warning or missing artifact (captures `VERIFY_SUPERFICIAL_CHECK` / `VERIFY_PREMATURE_TERMINATION`)

---

## 4. Models, Baselines & Ablation Study

### Models Trained & Persisted (`models/`):
1. **Prompt-Injection Classifier:** `FeatureUnion([Word TF-IDF (1,2), Char_wb TF-IDF (3,5)])` → `CalibratedClassifierCV(LogisticRegression(C=2.0, class_weight="balanced"))`.
2. **Step-Fault Ranker (`C³-Ranker`):** `HistGradientBoostingClassifier` (with isotonic/Platt probability calibration) scoring each span's probability of being the decisive root-cause step, ranked within each trace.
3. **MAST Mode Classifier:** `RandomForestClassifier` trained on the attributed step's feature vector + trace-level summary features to classify the exact MAST/Security failure mode.
4. **C³-Attributor (Full System):** Combines `C³-Ranker` Top-3 candidates with **Counterfactual Replay Verification** — re-ranking candidates by $\text{Score}_{\text{C}^3}(s_i) = 0.55 \cdot P_{\text{ML}}(s_i) + 0.45 \cdot \Delta_{\text{cf}}(s_i)$, where $\Delta_{\text{cf}}(s_i)$ is the verified causal recovery score from replaying an intervention at step $i$.

### Baselines Compared on the Exact Same Held-Out Test Split:
1. **Baseline 1 — Random Step Selection**
2. **Baseline 2 — Last-Step / Last-Error Heuristic** (what naive stack-trace debugging does)
3. **Baseline 3 — Rule-Only MAST Heuristic** (deterministic pattern checks without ML or counterfactual replay)
4. **Baseline 4 — Semantic/Lexical Drift Only** (ranks step with largest goal/context divergence)
5. **Ablation A — ML Step-Fault Ranker Only (no Counterfactual Replay)**
6. **Proposed — Full C³-Attributor (ML Ranker + Taint Firewall + Counterfactual Replay)**

### Evaluation Metrics (Never Fabricated — Computed Live & Saved to `EVALUATION_REPORT.md`):
- **Step Attribution:** Top-1 Exact Step Accuracy, Top-3 Step Accuracy, Mean Reciprocal Rank (MRR), Agent-Level ("Who") Accuracy, MAST Mode Macro-F1, Expected Calibration Error (ECE).
- **Injection Defense:** Precision, Recall, F1, ROC-AUC, Hard-Negative False Positive Rate (FPR).
- **Runtime:** Mean attribution latency (ms/trace) on CPU.
