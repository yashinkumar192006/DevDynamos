# ContextShield — runnable integration examples

These examples show how an **existing** AI agent integrates with
ContextShield without rebuilding its architecture: its protected data
retrieval (and model-invocation) paths are wrapped so they pass through the
gateway.

> **Installing the SDK does not protect an agent by itself.** Protection
> applies exactly to the paths that go through the gateway. If the agent can
> still read protected data directly, or call an LLM with raw data, nothing
> is enforced. Every example marks the single approved access path — in real
> systems you would *remove or restrict* the direct paths (see
> [`../docs/integration-guide.md`](../docs/integration-guide.md) §“Honest
> security boundary”).

## Prerequisites

1. **Gateway running** against the migrated + seeded demo database:

   ```powershell
   cd backend
   .venv\Scripts\python.exe -m alembic upgrade head
   .venv\Scripts\python.exe -m app.seed
   .venv\Scripts\uvicorn.exe app.main:app --port 8000
   ```

2. **Credentials via environment variables** — nothing is hardcoded:

   ```powershell
   $env:CONTEXTSHIELD_BASE_URL = "http://localhost:8000"   # optional (default)
   $env:CONTEXTSHIELD_USERNAME = "<seed user, e.g. natalie.brooks>"
   $env:CONTEXTSHIELD_PASSWORD = "<seeded demo password>"   # see backend/app/seed.py
   ```

   Or use an **agent credential** (service account):

   ```powershell
   cd backend
   .venv\Scripts\python.exe -m app.create_service_account --name demo-agent `
       --scopes privacy:request,order_records:read
   $env:CONTEXTSHIELD_API_KEY = "<the key shown once>"
   ```

3. Run from the repository root (the SDK is imported from `sdk/` if not
   installed; `pip install -e sdk` works too):

   ```powershell
   python examples/demo_end_to_end.py     # or any file in the table below
   python examples/agent_full_flow.py     # full governed sequence + fail-closed
   python examples/devhost_demo.py        # ten-scenario DEVHOST demonstration
   ```

## The examples

| Example | Seeded identity | Integration pattern |
|---|---|---|
| [`demo_end_to_end.py`](demo_end_to_end.py) | `natalie.brooks` (customer) | Submit a request, handle a **BLOCK**, use an approved result (incl. mock-LLM summary) and read back the audit trail. |
| [`simple_agent.py`](simple_agent.py) | `sarah.chen` (HR manager) | **1. Simple existing Python agent** — its one protected lookup method now calls the gateway. |
| [`tool_connector_agent.py`](tool_connector_agent.py) | `eve.johnson` (support agent) | **2. Agent with a tool / data connector** — the tool is wrapped; masking applies per policy. |
| [`llm_precheck_agent.py`](llm_precheck_agent.py) | `sarah.chen` (HR manager) | **3. Gateway pre-flight before the agent's own LLM** — blocked/injection attempts never reach the model. |
| [`agent_full_flow.py`](agent_full_flow.py) | `sarah.chen` (HR manager) | **Full governed sequence** — intent → SDK → identity/policy → retrieval → transformations → approved context → mock LLM → output guard; plus a blocked injection attempt and a gateway-unreachable fail-closed check. |
| [`devhost_demo.py`](devhost_demo.py) | six seeded roles | **DEVHOST demonstration** — ten scenarios (intern BLOCK, HR ALLOW, analyst AGGREGATE, customer isolation, injection, audit, SDK, browser) with expected vs actual output. Runbook: [`../docs/devhost-demo.md`](../docs/devhost-demo.md). |
| [`http/README.md`](http/README.md) | any | **4. Generic HTTP integration** for non-Python agents (curl / JavaScript / PowerShell). |

Demo passwords for the seeded identities live in `backend/app/seed.py`
(`USERS`); they are demo-only and must never be used elsewhere.

## What each example deliberately shows

* **BLOCK is a normal outcome** — the SDK returns it as a typed result
  (`.blocked`, per-field reason codes); `raise_if_blocked()` exists for
  exception-style handling.
* **Purpose is required context, not proof** — it is an input to policy
  evaluation, never a permission of its own.
* **No raw values leave the gateway** — approved results are already
  transformed (masked/generalized/aggregated) before the agent sees them.
* **Model stages are gated** — the gateway only invokes a provider after a
  grant, and inspects the output before release; ``include_llm_response``
  uses the default **mock provider** here, so examples run without API keys.
