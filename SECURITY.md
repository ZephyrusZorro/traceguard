# Security Architecture & Threat Model — TraceGuard

## 1. Threat Model (STRIDE + OWASP LLM Top 10)

| Threat | Attack Vector | Mitigation Implemented in TraceGuard |
|---|---|---|
| **Indirect Prompt Injection (LLM01)** | Attacker embeds directives inside external email, web filing, or ticket tool output. | Calibrated Word+Char TF-IDF + Logistic Regression detector + CaMeL provenance taint lattice (`UNTRUSTED_TOOL` taint propagation). |
| **Sensitive Info Exfiltration (LLM06)** | Tainted agent invokes `send_email`/`http_post`/`transfer_funds` carrying `SECRET_DATA`. | `CapabilityFirewall` enforces `CAP-002-TAINTED-SINK-EXFILTRATION`, flagging/blocking tainted flows to external sinks. |
| **Excessive Agency (LLM08)** | Subordinate agent calls privileged tool outside its role, or diagnostic agent auto-modifies security rules. | `CAP-004-ROLE-TOOL-BOUNDARY` allowlist checks + **Human-in-the-Loop Policy Approval Gate** (`PENDING_APPROVAL` requires explicit `admin` approval). |
| **Prompt Injection via Telemetry** | Malicious trace payload attempts to hijack optional Ollama diagnostic summary. | Trace data strictly wrapped in `<DIAGNOSIS_DATA>` untrusted delimiters; core ML & counterfactual logic is 100% deterministic and never executes LLM-generated code/SQL. |
| **SSRF via Webhooks** | Malicious user registers `http://169.254.169.254/` or private RFC1918 IP as webhook target. | `validate_webhook_url()` rejects non-HTTP schemes, link-local/metadata IPs, and private networks (localhost configurable via `TRACEGUARD_ALLOW_LOCALHOST_WEBHOOKS`). |
| **Webhook Spoofing** | Third party sends forged alerts to downstream n8n/Slack receiver. | Every outbound webhook is signed with `X-TraceGuard-Signature: sha256=<HMAC-SHA256>`. |
| **Unauthorized API Mutation** | Unauthenticated or low-privilege client approves policies or registers webhooks. | Role-based API key enforcement (`viewer`, `analyst`, `admin`) + per-IP sliding-window rate limiter + immutable `audit_logs` table. |

## 2. Secrets & Local Defaults
Local development keys in `config.py` (`tg-admin-local-dev-key`, `tg-webhook-hmac-dev-secret`) are strictly for local offline evaluation and MUST be overridden via `TRACEGUARD_*` environment variables in any shared or deployed environment.
