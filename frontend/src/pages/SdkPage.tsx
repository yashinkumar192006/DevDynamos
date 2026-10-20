/**
 * SDK & Integration — developer documentation for calling the gateway.
 *
 * This page is static documentation: it performs no authorization and
 * renders no protected data. Code samples mirror `sdk/README.md` and the
 * real HTTP contract; the gateway URL shown is public configuration only.
 */

import type { ReactNode } from 'react'

import { Callout, Card, KeyValue, PageHeader } from '../components/ui'
import { API_BASE_URL } from '../lib/api/client'

const PYTHON_SNIPPET = `from contextshield import ContextShieldClient

# Credentials come from the environment (never hardcode them):
#   CONTEXTSHIELD_USERNAME + CONTEXTSHIELD_PASSWORD
#   or CONTEXTSHIELD_API_KEY / CONTEXTSHIELD_TOKEN
client = ContextShieldClient.from_env()

result = client.secure_request(
    resource="order_records",
    data_fields=["order_id", "status"],
    purpose="order_status",
    target_entity="ORD0001",
)

if result.blocked:
    # BLOCK is a normal outcome: nothing was retrieved or disclosed.
    reasons = [d.reason_code for d in result.fields.values()]
    print("Not disclosed:", reasons)
else:
    # Values are already authorized and transformed by the gateway.
    print(result.granted_values())`

const HTTP_SNIPPET = `curl -s -X POST "$CONTEXTSHIELD_BASE_URL/api/v1/privacy/secure-request" \\
  -H "X-API-Key: $CONTEXTSHIELD_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "resource": "order_records",
    "data_fields": ["order_id", "status"],
    "purpose": "order_status",
    "target_entity": "ORD0001"
  }'`

function CodeBlock({ title, code }: { title: string; code: string }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-4 py-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
        {title}
      </div>
      <pre className="overflow-x-auto px-4 py-4 text-xs leading-relaxed text-slate-100">
        <code>{code}</code>
      </pre>
    </div>
  )
}

function Section({
  title,
  children,
}: {
  title: string
  children: ReactNode
}) {
  return (
    <Card className="mb-5 px-5 py-5">
      <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
      <div className="mt-3 space-y-3 text-sm text-slate-600">{children}</div>
    </Card>
  )
}

export default function SdkPage() {
  return (
    <div>
      <PageHeader
        title="SDK & Integration"
        description="Integrate an existing Python agent — or any HTTP client — with the gateway. The SDK is a convenience layer over the same REST API; every decision is still made server-side."
      />

      <Callout tone="warning" title="The integration boundary (read this first)">
        Installing the SDK does not protect an agent by itself. Protection
        applies exactly to the paths that go through the gateway. The agent’s
        protected <em>retrieval</em> and <em>model-invocation</em> paths must be
        replaced or wrapped, and the underlying data source must independently
        enforce authorization for anything that bypasses the gateway.
      </Callout>

      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card className="px-5 py-4 lg:col-span-2">
          <h2 className="text-sm font-semibold text-slate-900">
            Install &amp; configure
          </h2>
          <div className="mt-3 space-y-3 text-sm text-slate-600">
            <p>
              From the repository root (the package is typed and supports
              Python 3.10+; distribution to PyPI is prepared but not published):
            </p>
            <CodeBlock title="PowerShell" code={'pip install -e sdk'} />
            <p>
              Credentials are read from environment variables — never place
              them in source code or the browser.
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <KeyValue label="Gateway URL" mono>
                CONTEXTSHIELD_BASE_URL (default http://localhost:8000)
              </KeyValue>
              <KeyValue label="Human login" mono>
                CONTEXTSHIELD_USERNAME + CONTEXTSHIELD_PASSWORD
              </KeyValue>
              <KeyValue label="Agent / service" mono>
                CONTEXTSHIELD_API_KEY
              </KeyValue>
              <KeyValue label="Pre-issued JWT" mono>
                CONTEXTSHIELD_TOKEN
              </KeyValue>
            </div>
          </div>
        </Card>

        <Card className="px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-900">
            This console’s gateway
          </h2>
          <div className="mt-3 space-y-3">
            <KeyValue label="API base URL" mono>
              {API_BASE_URL}
            </KeyValue>
            <p className="text-xs text-slate-500">
              Public configuration only. Provider API keys, JWTs, database
              credentials, and passwords never reach the browser.
            </p>
            <p className="text-xs text-slate-500">
              Full guides: <code>docs/integration-guide.md</code> and{' '}
              <code>sdk/README.md</code> in the repository.
            </p>
          </div>
        </Card>
      </div>

      <div className="mt-5">
        <CodeBlock title="Python SDK — governed request" code={PYTHON_SNIPPET} />
      </div>

      <div className="mt-5">
        <CodeBlock title="Any language — equivalent HTTP call" code={HTTP_SNIPPET} />
      </div>

      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Section title="Decision handling">
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="text-slate-500">
                <tr>
                  <th className="py-1 pr-3 font-semibold">Decision</th>
                  <th className="py-1 font-semibold">What the agent may do</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                <tr>
                  <td className="py-2 pr-3 font-mono">ALLOW</td>
                  <td className="py-2">
                    Use the returned values, already authorized and transformed.
                  </td>
                </tr>
                <tr>
                  <td className="py-2 pr-3 font-mono">PARTIAL_ALLOW</td>
                  <td className="py-2">
                    Use only each field’s returned value; withheld fields have
                    no value.
                  </td>
                </tr>
                <tr>
                  <td className="py-2 pr-3 font-mono">BLOCK</td>
                  <td className="py-2">
                    Disclose nothing; surface the safe reason code. A normal
                    outcome, not an exception.
                  </td>
                </tr>
                <tr>
                  <td className="py-2 pr-3 font-mono">ESCALATION_NEEDED</td>
                  <td className="py-2">
                    Wait for human/policy review; disclose nothing yet.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </Section>

        <Section title="Errors &amp; failure behavior">
          <ul className="list-disc space-y-1 pl-5 text-xs">
            <li>
              <code>AuthenticationError</code> / <code>PermissionDeniedError</code>{' '}
              — credential rejected (401) or identity not permitted (403).
            </li>
            <li>
              <code>ValidationError</code> / <code>NotFoundError</code> — request
              shape rejected or resource missing/out-of-scope.
            </li>
            <li>
              <code>GatewayError</code> / <code>GatewayUnavailableError</code> /{' '}
              <code>RequestTimeoutError</code> — gateway failures. Fail closed:
              never fall back to direct data access.
            </li>
            <li>
              <code>RequestBlockedError</code> /{' '}
              <code>RequestEscalatedError</code> — only if you opt in with{' '}
              <code>raise_if_blocked()</code>.
            </li>
          </ul>
        </Section>
      </div>

      <Callout tone="info" title="Runnable examples">
        The repository contains complete integrations:{' '}
        <code>examples/simple_agent.py</code>,{' '}
        <code>examples/tool_connector_agent.py</code>,{' '}
        <code>examples/llm_precheck_agent.py</code>,{' '}
        <code>examples/agent_full_flow.py</code>, and the language-agnostic{' '}
        <code>examples/http/README.md</code>. The DEVHOST demonstration lives in{' '}
        <code>docs/devhost-demo.md</code>.
      </Callout>
    </div>
  )
}
