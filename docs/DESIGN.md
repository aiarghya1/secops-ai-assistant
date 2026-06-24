# SecOps AI Assistant — Design Document

## 1. Architecture and Approach

The SecOps AI Assistant is designed as a **multi-layered, agentic triage pipeline**. Instead of passing raw logs directly to an LLM, the system uses a structured pipeline to normalize, enrich, and contextualize alerts before analysis. 

### Core Components
1. **Ingestion & Normalization (Adapters)**: 
   - Accepts diverse JSON payloads (Splunk, CrowdStrike, Suricata).
   - Normalizes disparate formats into an internal `OCSF-lite` schema (`NormalizedAlert`).
   - Auto-detects formats and uses heuristic parsing for unknown structures.

2. **Parallel Enrichment Engine (Context Layer)**:
   - Queries multiple providers concurrently (`asyncio.gather`): IP Reputation, Domain Intel, GeoIP, Asset Context (CMDB), and Historical Behavior.
   - **Crucial Design Choice**: Implements strict timeouts. Partial enrichment is accepted to maintain triage latency targets (e.g., if WHOIS is slow, the LLM still analyzes the alert but with a note about missing data).

3. **AI Analysis Layer (Reasoning Layer)**:
   - Uses a multi-provider LLM abstraction (OpenAI / Gemini) with automatic failover and exponential backoff.
   - Enforces a strict JSON output schema for the verdict, evidence, MITRE mappings, and recommended actions.
   - Includes a post-processing step to detect hallucinations (e.g., cross-referencing extracted IOCs against the original alert).

4. **Presentation Layer**:
   - FastAPI backend providing REST endpoints and WebSocket for live updates.
   - Vanilla JS frontend utilizing glassmorphism and modern design principles to provide an immediate "wow factor" and high usability for analysts.

---

## 2. Key Assumptions

- **LLM Capabilities**: The system assumes the use of highly capable reasoning models (GPT-4o or Gemini 1.5 Pro/Flash) that can adhere strictly to JSON schemas and follow chain-of-thought instructions.
- **Enrichment Data Quality**: The system assumes that asset context (CMDB) is the primary determinant of severity (e.g., a malware alert on a Tier-0 Domain Controller is inherently more critical than on an isolated guest network).
- **Analyst Workflow**: The assistant is a "Copilot," not an autonomous remediation agent. It recommends actions but expects a human-in-the-loop for execution.

---

## 3. Tradeoffs

| Dimension | Decision | Rationale & Tradeoff |
| :--- | :--- | :--- |
| **Latency vs. Accuracy** | Parallel enrichment + fast LLMs | Goal is triage within 3-8 seconds. We trade exhaustive deep-dive capability (which might take minutes) for speed, enabling the system to keep up with high alert volumes. |
| **Cost vs. Quality** | Support for "mini/flash" models | By heavily structuring the prompt and providing rich context, smaller, cheaper models (GPT-4o-mini, Gemini Flash) can perform triage at <$0.01 per alert, trading nuanced deep analysis for massive scalability. |
| **Flexibility vs. Rigidity** | OCSF-lite Normalization | Mapping all alerts to a common schema loses some vendor-specific metadata, but simplifies the LLM prompt and ensures consistent enrichment logic. |
| **Persistence** | SQLite | Used for prototype simplicity and zero-dependency setup. In production, this would be swapped for PostgreSQL and Redis. |

---

## 4. Limitations and Failure Modes

### Known Limitations
- **Context Window Limits**: Extremely large alerts (e.g., massive JSON arrays of process trees) may exceed token limits or dilute the LLM's attention.
- **Mock Data**: Threat intelligence is currently mocked. Real-world API integration requires managing rate limits and API keys.

### Anticipated Failure Modes & Mitigations
1. **LLM Hallucination of IOCs**: 
   - *Mitigation*: The `AlertAnalyzer._post_process()` method explicitly checks if the IOCs extracted by the LLM actually exist in the original alert payload.
2. **Provider Outages (OpenAI/Gemini down)**: 
   - *Mitigation*: Multi-provider failover. If OpenAI fails, it falls back to Gemini. If both fail, it degrades gracefully to returning just the enrichment data.
3. **Prompt Injection via Alert Fields**: 
   - *Mitigation*: Alert data is injected into a specific data section of the prompt, not interpreted as instructions. Structured output schema enforces the expected response format.
4. **Enrichment API Rate Limiting**: 
   - *Mitigation*: Database-backed TTL caching (`enrichment_cache` table) prevents redundant lookups for noisy indicators.

---

## 5. Example Outputs

### Scenario: Brute Force from Tor Exit Node
* **Input**: Splunk alert indicating 8 failed SSH logins from `185.220.101.34` to `WS-FINANCE-042`.
* **Enrichment**: 
  - IP Reputation identifies the IP as a Tor exit node with a 92/100 malicious score. 
  - Asset Context identifies the host as a PCI-scope financial workstation.
  - Historical data shows 2 previous alerts for this IP.
* **AI Output**: 
  - **Verdict**: `true_positive` (Confidence: 88%)
  - **Severity**: `high` (escalated due to PCI-scope target)
  - **Root Cause**: Automated credential stuffing via Tor network targeting a sensitive financial asset.
  - **Action**: "Block IP at perimeter firewall" (Immediate/Automated) and "Lock admin_user account" (Immediate/Automated).

### Scenario: C2 Beaconing
* **Input**: Suricata alert for suspicious User-Agent to `198.51.100.23` from a developer workstation.
* **Enrichment**: IP is hosted in Russia (PIN Data Center) with a 95/100 score and 3 prior critical alerts.
* **AI Output**:
  - **Verdict**: `true_positive` (Confidence: 90%)
  - **Severity**: `critical` (Developer workstation has code access, risking supply chain compromise).
  - **Action**: "Network isolate host immediately" and "Audit code commits for the past 30 days."
