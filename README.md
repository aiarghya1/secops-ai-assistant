# SecOps AI Assistant

![SecOps AI](https://img.shields.io/badge/Status-Prototype-blue) ![Python](https://img.shields.io/badge/Python-3.10+-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green)

An AI-powered assistant for Security Operations analysts to triage, enrich, and investigate security alerts automatically.

## Overview

The SecOps AI Assistant acts as a "Tier 1 AI Analyst." It ingests raw alerts from SIEMs (Splunk, CrowdStrike, Suricata), enriches them with contextual data (IP reputation, asset context, historical behavior), and uses an LLM (OpenAI or Google Gemini) to determine severity, identify root causes, and recommend actionable remediation steps.

**Key Features:**
- 🧠 **Multi-LLM Support**: Built-in support and automatic failover for OpenAI and Google Gemini.
- 🔌 **Universal Ingestion**: Adapters for Splunk, CrowdStrike, Suricata, plus heuristic parsing for unknown JSON formats.
- ⚡ **Parallel Enrichment**: Fast, asynchronous data enrichment with caching and strict timeouts.
- 🛡️ **Hallucination Guards**: Post-processing validates LLM claims against actual alert data.
- 💻 **Premium Dashboard**: A sleek, dark-mode web UI for analysts to review AI investigations in real-time.

## Quickstart

### 1. Installation

```bash
git clone https://github.com/secops-ai/secops-ai-assistant.git
cd secops-ai-assistant

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
make install
```

### 2. Configuration

Copy the environment template:
```bash
cp .env.example .env
```

Add your API keys to `.env`:
```env
OPENAI_API_KEY=sk-...
# OR
GOOGLE_API_KEY=AIza...
```
*(If no keys are provided, the app runs in **Demo Mode**, utilizing pre-computed responses for the sample alerts to demonstrate functionality without incurring costs).*

### 3. Run the App

```bash
make dev
```

Open your browser to: **http://localhost:8000**

## Architecture

See [docs/DESIGN.md](docs/DESIGN.md) for a detailed architecture overview, tradeoff analysis, and failure mode mitigation strategies.

## Project Structure

- `app/adapters/` - Parsers to convert SIEM-specific JSON into a normalized internal schema.
- `app/ai/` - Multi-LLM client, prompts, and the core `AlertAnalyzer` logic.
- `app/enrichment/` - Parallel data providers (IP Reputation, GeoIP, CMDB context, Historical data).
- `app/models/` - Pydantic schemas enforcing strict data structures.
- `app/routes/` - FastAPI REST endpoints.
- `app/static/` - Vanilla JS / CSS frontend dashboard.
- `samples/` - Test alert JSON files for different SIEM formats.

## API Usage

Ingest an alert programmatically:

```bash
curl -X POST http://localhost:8000/api/alerts/ingest \
  -H "Content-Type: application/json" \
  -d @samples/splunk_brute_force.json
```
