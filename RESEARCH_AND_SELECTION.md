# Industry Research, Ideation & Strategic Selection

## 1. Industry & Academic Research Synthesis (2024–2026)

Before selecting a project, we surveyed recent peer-reviewed AI/ML research, open-source infrastructure standards, enterprise engineering pain points, and 2025–2026 AI Engineer hiring criteria:

### A. Verified Academic & Benchmark Foundations
1. **Automated Failure Attribution in Multi-Agent Systems (*Who&When*, ICML 2025 Spotlight, arXiv:2505.00212)** — Zhang, Yin et al. (Penn State, Duke, UW, NTU, Meta, Google DeepMind). Formalized *Automated Failure Attribution (AutoFA)* and released the 184-task `Who&When` benchmark (`Kevin355/Who_and_When`). Key finding: even frontier reasoning models (o1, DeepSeek-R1) achieve at best **53.5% agent-attribution accuracy** and **14.2% exact step-localization accuracy**.
2. **Multi-Agent Failure Taxonomy (*MAST*, arXiv:2503.13657, 2025)** — UC Berkeley et al. Analyzed 1,600+ traces across 7 MAS frameworks (MetaGPT, ChatDev, AutoGen, Magentic-One) with $\kappa = 0.88$ inter-annotator agreement, defining **14 failure modes across 3 pillars**: System Design/Specification, Inter-Agent Misalignment, and Task Verification/Termination.
3. **Counterfactual Replay & Constraint-Based Diagnosis (*AgenTracer*, arXiv:2509.03312; *AgentRx*, Microsoft Research, arXiv:2602.02475)** — Showed that combining constraint violation auditing with **counterfactual replay** (rewinding to step $k$, intervening, and checking whether failure disappears) dramatically improves localization accuracy over passive log inspection.
4. **Prompt Injection & Defense-by-Design (*AgentDojo*, NeurIPS 2024; *CaMeL: Defeating Prompt Injections by Design*, Google DeepMind / ETH Zurich, 2025)** — Demonstrated that prompt-engineering defenses fail against indirect prompt injections embedded in tool outputs; provable security requires **Control-Flow / Data-Flow separation**, **taint/provenance tracking**, and **capability-based policy enforcement** on tool calls.

### B. Open-Source Infrastructure & Industry Gaps
- **OpenTelemetry GenAI Semantic Conventions (`open-telemetry/semantic-conventions-genai`)**: Standardizes `gen_ai.operation.name` (`chat`, `execute_tool`, `invoke_agent`), `gen_ai.agent.name`, token usage, and parent-child span trees.
- **Existing OSS Tools (Langfuse, Arize Phoenix, OpenLIT)**: Excellent at OTLP trace ingestion, cost dashboards, and LLM-as-a-judge scoring, **but they lack**:
  1. Integrated **step-level causal failure localization** (who/when/MAST-mode) backed by a trained structural+semantic ML model.
  2. **Deterministic counterfactual time-travel replay** that proves whether patching step $k$ fixes the terminal failure.
  3. **CaMeL-style taint & capability firewalling** for indirect prompt injection and tool exfiltration.
- **AI Engineer Hiring Signal (2025–2026)**: Companies filter out prompt-wrapper portfolios and prioritize candidates who build **automated evaluation harnesses, OpenTelemetry observability, stateful multi-agent orchestration, and AI security guardrails**.

---

## 2. Candidate Concept Generation (8 Distinct Concepts)

| # | Concept | Core Problem | Target User | Proposed Intelligent Mechanism | Why Distinct from Existing Portfolio |
|---|---|---|---|---|---|
| **1** | **TRACEGUARD** — Causal Multi-Agent Failure Attribution, Prompt-Injection Capability Firewall & Counterfactual Replay Platform | Production multi-agent systems fail via cascading errors & indirect prompt injections; teams cannot pinpoint *which agent, which step, or why* without expensive manual debugging. | AI/ML Engineers, Agent Platform Teams, AI Security Engineers | **C³-Attributor**: Trained ML Step-Fault Classifier + Taint/Capability Policy Firewall (CaMeL-inspired) + Deterministic Counterfactual Replay Verifier over OTel `gen_ai.*` traces. | Zero overlap with any of Faris's 19 repos; unites AI/ML research + Cybersecurity + Backend/Observability. |
| **2** | **AegisSOC** — Autonomous Log Anomaly & MITRE ATT&CK Graph Correlator | SOC analysts drown in false-positive SIEM alerts across multi-host logs. | Security Operations Analysts | Isolation Forest + Temporal Graph Neural/Markov Correlator mapping log bursts to MITRE ATT&CK kill chains. | Strong cybersecurity fit, but less AI-native novelty than agent reliability/security. |
| **3** | **SpecRoute** — Semantic-Cache & Speculative Cost-Aware LLM Router | Production LLM apps waste 40–60% spend routing trivial queries to frontier models. | AI Infra Engineers | Trained difficulty/confidence router + semantic cache + conformal latency-budget allocator. | Useful infra, but misses Faris's cybersecurity goal and multi-agent depth. |
| **4** | **FedTriage** — Differentially-Private Federated Clinical Risk Engine | Hospitals cannot pool patient data for ML training due to privacy laws. | Healthcare ML Engineers | Simulated FedAvg with $(\epsilon, \delta)$-DP noise calibration and fairness auditing. | **Overlaps** Faris's 4 healthcare repos (`vaani-clinical`, `nephroguard`, `health-docker`, `vox-ai`). |
| **5** | **VeriSynth** — Provenance-Verified Synthetic Data & Leakage-Free AutoML | Tabular ML pipelines suffer silent data leakage and synthetic drift. | Data Scientists | Leakage graph auditor + CTGAN/copula synthesizer + Wasserstein fidelity gate. | **Directly overlaps** his final-year project `LeakageGuard`. |
| **6** | **ArchDrift** — Multimodal Code-to-Architecture Drift & Vulnerability Verifier | Codebases silently diverge from architecture specs and introduce OWASP flaws. | Staff Engineers / AppSec | AST + Call-Graph GNN anomaly detector + static taint analyzer. | **Overlaps** `tark-ai` (AST code studio). |
| **7** | **SoundPulse** — Edge-Quantized Acoustic Predictive Maintenance | Industrial bearings fail unexpectedly between maintenance cycles. | OT/IoT Engineers | INT8-quantized 1D-CNN/spectrogram anomaly detector with edge drift alerts. | **Overlaps** `parallax` (cyber-physical digital twin). |
| **8** | **ClaimMesh** — Probabilistic Multi-Modal Fact-Verification & Citation Graph | Analysts struggle to verify multi-document claims with contradictory sources. | Research Analysts | Hybrid retrieval + NLI contradiction graph + belief propagation calibration. | **Overlaps** `kuber-datacore` (financial document & relationship graph). |

---

## 3. Weighted Evaluation Matrix (100 Points)

| Criterion (Weight) | 1. TraceGuard | 2. AegisSOC | 3. SpecRoute | 4. FedTriage | 5. VeriSynth | 6. ArchDrift | 7. SoundPulse | 8. ClaimMesh |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Alignment with profile (15) | **14** | 12 | 13 | 10 | 11 | 11 | 9 | 11 |
| Fills critical skill gaps (15) | **15** | 13 | 11 | 11 | 9 | 11 | 10 | 10 |
| AI/ML engineering depth (15) | **14** | 12 | 13 | 13 | 12 | 11 | 12 | 13 |
| Real-world usefulness (10) | **10** | 9 | 9 | 7 | 8 | 8 | 7 | 8 |
| Originality & research potential (10) | **10** | 7 | 8 | 7 | 7 | 7 | 6 | 8 |
| Full-stack & backend sophistication (10) | **10** | 9 | 8 | 7 | 7 | 8 | 7 | 8 |
| Career & recruitment value (10) | **10** | 9 | 9 | 7 | 7 | 8 | 6 | 7 |
| Technical feasibility (5) | **5** | 5 | 5 | 4 | 4 | 4 | 4 | 5 |
| Interconnected systems potential (5) | **5** | 4 | 4 | 3 | 3 | 4 | 3 | 4 |
| Demonstrability & benchmarking (5) | **5** | 4 | 5 | 4 | 4 | 4 | 4 | 4 |
| **TOTAL (100)** | **98** | **84** | **85** | **73** | **72** | **76** | **68** | **78** |

---

## 4. Final Selection Rationale: **TRACEGUARD**

**Selected Project:** **TraceGuard** — *Causal Multi-Agent Failure Attribution, Prompt-Injection Capability Firewall & Counterfactual Replay Platform*.

**Why TraceGuard Wins Decisively:**
1. **Unifies all three pillars of Faris's career trajectory:** B.E. AI & ML (trained step-fault & injection ML models + rigorous benchmarking/ablations) + Backend/Full-Stack Systems (OTel `gen_ai.*` ingestion, FastAPI, SQLite WAL, WebSockets, MCP server, n8n webhooks, React/TS forensics desk) + Cybersecurity (CaMeL-inspired information-flow taint tracking & capability firewalling).
2. **Directly anchored in 2025–2026 frontier research:** Operationalizes *Who&When* (ICML 2025), *MAST* (UC Berkeley 2025), *AgentRx* (Microsoft 2026), *AgenTracer* (2025), *AgentDojo* (NeurIPS 2024), and *CaMeL* (Google DeepMind 2025).
3. **Zero portfolio duplication:** Complements rather than repeats `relaydesk`, `market-cortex`, `tark-ai`, `lablens`, `vox-ai`, `parallax`, and `LeakageGuard`.
4. **100% locally reproducible & verifiable:** Runs completely offline with trained scikit-learn models, deterministic + optional local Ollama (`llama3.2:3b`) agent execution, real counterfactual replay, and genuine benchmark evaluation without requiring paid API keys.

### Open-Source Lineage & Attribution Plan
- **Inspired by / aligned with:** OpenTelemetry GenAI Semantic Conventions (`gen_ai.*`), MAST 14-mode failure taxonomy, Who&When attribution task framing, and CaMeL capability-flow security model.
- **External dependencies (standard libraries/packages):** FastAPI, Pydantic v2, scikit-learn, NumPy, NetworkX, SQLite, httpx, React, TypeScript, Vite, Tailwind CSS, Recharts/SVG, Lucide Icons, MCP SDK.
- **Original contributions built from scratch:**
  1. **C³-Attributor Engine** (structural causal trajectory graph + trained Gradient-Boosted/Logistic step-fault ranker + MAST classifier + counterfactual replay causal verifier).
  2. **Taint-Aware Capability Firewall** (provenance lattice + trained TF-IDF/Logistic indirect prompt-injection detector + capability policy evaluator).
  3. **4-Agent Diagnostic Council** with strict Pydantic I/O contracts, retry/timeout budgets, contradiction detection, and human-in-the-loop policy approval gates.
  4. **End-to-End Forensic Platform** (OTel ingestor, WebSocket live event bus, MCP server, webhook/n8n automation dispatcher, and React/TS time-travel debugging workstation).
