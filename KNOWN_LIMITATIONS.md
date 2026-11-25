# Known Limitations & Future Research Directions — TraceGuard

1. **Synthetic vs. Real-World Multi-Agent Trace Distribution:**  
   `TraceBench-MAS` (360 traces) is a reproducible synthetic benchmark with distractor warning/latency spans and stripped metadata flags. While it validly separates naive heuristics (`8.3%`–`25.0%`) and rule-only detectors (`87.5%`) from our learned C³-Attributor (`100.0%`), real-world production traces (e.g., *Who&When* GAIA/AssistantBench logs) contain open-ended reasoning ambiguity where raw ML accuracy will be lower. **Next step:** build an ingestion adapter for `Kevin355/Who_and_When` Parquet traces and benchmark C³-Attributor on human-annotated external traces.
2. **Hard-Negative False Positive Rate on Pure Text Classification:**  
   On unseen hard-negative benign security runbooks, the TF-IDF + Logistic Regression injection model exhibits a `29.1%` FPR. TraceGuard mitigates this operationally via its CaMeL capability lattice (only blocking when untrusted taint reaches an external sink or co-exists with `SECRET_DATA`), but replacing TF-IDF with a fine-tuned small DeBERTa/ModernBERT encoder would further reduce hard-negative FPR.
3. **Deterministic Counterfactual Replay vs. Live LLM Re-Execution:**  
   Counterfactual replay executes deterministic state-transition & invariant verification rather than re-invoking live external APIs or paid frontier LLMs. This guarantees reproducibility, safety (no accidental side effects), and `<40 ms` latency, at the cost of not simulating stochastic LLM phrasing changes.
4. **Local-First Storage & Docker Verification:**  
   SQLite WAL provides zero-daemon local reproducibility, but high-throughput multi-replica deployments should swap the repository layer to PostgreSQL + Redis/Kafka. Dockerfiles and `docker-compose.yml` are provided and CI-ready, though Docker Desktop was not running on the host machine during this session to build the containers locally.
5. **Optional Local Ollama Synthesis:**  
   Ollama (`llama3.2:3b`) narrative summarization is supported behind `use_ollama=True` with strict `<DIAGNOSIS_DATA>` untrusted-data framing and 3.5s timeout fallback, and defaults to off so all tests and workflows remain deterministic.
