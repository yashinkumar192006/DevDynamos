# Generic HTTP integration (no Python required)

The Python SDK is a **native convenience layer** — every gateway feature is a
plain HTTP API. Non-Python agents (Node.js, Go, Java, .NET, curl scripts, …)
integrate by calling the same endpoints with their own thin adapter.

The contract you need:

| Concern | Value |
|---|---|
| Base URL | `http://localhost:8000` (configurable per deployment) |
| Human auth | `POST /api/v1/auth/login` → `access_token` (JWT), sent as `Authorization: Bearer <token>` |
| Agent auth | Service-account API key (created with `python -m app.create_service_account`), sent as `X-API-Key: <key>` |
| Secure request | `POST /api/v1/privacy/secure-request` |
| Audit trail | `GET /api/v1/audit/events` and `/api/v1/audit/events/{id}` |
| Content type | `application/json` |

> Remember: adding the header is not the protection. Your agent's protected
> **retrieval** and **model-call** paths must call this API instead of the
> underlying data source. See `../../docs/integration-guide.md`.

## 1. Authenticate

```bash
# Human identity (demo accounts are seeded in backend/app/seed.py)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"natalie.brooks","password":"<seeded demo password>"}' \
  | jq -r '.access_token')
```

Agent identity instead of a login:

```bash
export CONTEXTSHIELD_API_KEY="<key shown once by create_service_account>"
# then send: -H "X-API-Key: $CONTEXTSHIELD_API_KEY"
```

## 2. Submit a secure request

```bash
curl -s -X POST http://localhost:8000/api/v1/privacy/secure-request \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": "order_records",
    "data_fields": ["order_id", "status"],
    "purpose": "order_status",
    "target_entity": "ORD0001",
    "context": {"session_id": "my-agent-run-1"}
  }'
```

The response is the contract for every language:

```jsonc
{
  "request_id": "…",                  // correlation id (also in every audit event)
  "overall_decision": "ALLOW",        // ALLOW | PARTIAL_ALLOW | BLOCK | ESCALATION_NEEDED
  "reason_code": "NORM_MATCHED",
  "fields": {
    "order_id": {"action": "ALLOW", "value": "ORD0001", "reason_code": "NORM_MATCHED", "policy_id": "…", "policy_version": 3}
  },
  "records": [ {"order_id": "ORD0001", "status": "delivered"} ],  // approved rows only (null when blocked)
  "retrieved": true,
  "audit_id": "…",
  "timestamp": "2026-10-19T12:00:00Z"
}
```

Handling rules that apply to every client language:

* `BLOCK` is a **normal outcome**, not a transport error — nothing was
  disclosed, `records` is `null`, no model was invoked. Surface the refusal;
  never retry with tweaked fields to fish for data.
* `PARTIAL_ALLOW` means some fields were withheld or transformed — use each
  field's `value` (already masked/generalized/aggregated) and never the
  underlying source.
* `ESCALATION_NEEDED` means a human/policy review is required; do not
  disclose anything yet.
* Treat the payload as **final**: re-querying the source database to “fill
  gaps” bypasses the protection.

## 3. JavaScript / Node.js

```javascript
const BASE = process.env.CONTEXTSHIELD_BASE_URL ?? "http://localhost:8000";
const API_KEY = process.env.CONTEXTSHIELD_API_KEY; // never hardcode

async function secureRequest(body) {
  const response = await fetch(`${BASE}/api/v1/privacy/secure-request`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`gateway ${response.status}`);
  return response.json(); // branch on overall_decision
}

const result = await secureRequest({
  resource: "order_records",
  data_fields: ["order_id", "status"],
  purpose: "order_status",
  target_entity: "ORD0001",
});
if (result.overall_decision === "ALLOW") {
  for (const [name, decision] of Object.entries(result.fields)) {
    console.log(name, decision.action, decision.value);
  }
} else {
  console.log("not disclosed:", result.overall_decision);
}
```

## 4. PowerShell (Windows)

```powershell
$headers = @{ "X-API-Key" = $env:CONTEXTSHIELD_API_KEY }
$body = @{
  resource      = "order_records"
  data_fields   = @("order_id", "status")
  purpose       = "order_status"
  target_entity = "ORD0001"
} | ConvertTo-Json

$result = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8000/api/v1/privacy/secure-request" `
  -Headers $headers -ContentType "application/json" -Body $body

$result.overall_decision
$result.fields
```

## 5. Audit & explainability

```bash
curl -s "http://localhost:8000/api/v1/audit/events?limit=10&action=data_denied" \
  -H "Authorization: Bearer $TOKEN" | jq '.items[] | {timestamp, action, overall_decision, reason_codes}'

curl -s "http://localhost:8000/api/v1/audit/events/<event-id>" \
  -H "Authorization: Bearer $TOKEN" | jq '{request_id, decisions, llm, transformations}'
```

Visibility is enforced server-side: admins see the full trail, compliance
roles the privacy pipeline, everyone else only their own events; 404 means
“missing **or** out of scope” (existence is not disclosed).

## 6. Errors

| Status | Meaning | Client action |
|---|---|---|
| 401 | Missing/invalid credential | Re-authenticate (human login / rotate key) |
| 403 | Verified identity not permitted (incl. out-of-scope audit queries) | Surface; fix identity/permission setup |
| 404 | Missing or out-of-scope resource | Do not probe further |
| 422 | Request shape rejected | Fix the request; never bypass the gateway |
| 5xx | Gateway/backend failure | **Fail closed** — do not fall back to direct data access |

Policy decisions (`BLOCK`, …) arrive as **HTTP 200** responses — only
transport/validation problems are HTTP errors.
