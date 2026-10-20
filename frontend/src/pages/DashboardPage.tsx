/**
 * Dashboard — real metrics from `GET /api/v1/dashboard/overview`.
 *
 * The endpoint aggregates the *visible* audit trail for the signed-in
 * identity (own events / privacy trail / full trail). If nothing has been
 * recorded yet, an explicit empty state is shown — statistics are never
 * fabricated.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { Badge, DecisionBadge, StatusBadge } from '../components/Badges'
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  StatCard,
} from '../components/ui'
import { fetchDashboardOverview } from '../lib/api/dashboard'
import { formatDateTime, scopeLabel } from '../lib/format'
import { useApiResource } from '../lib/useApi'

const WINDOWS = [7, 14, 30]

function chartDate(value: string): string {
  const date = new Date(`${value}T00:00:00Z`)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  })
}

export default function DashboardPage() {
  const [windowDays, setWindowDays] = useState(14)
  const { data, loading, error, reload } = useApiResource(
    () => fetchDashboardOverview(windowDays),
    [windowDays],
  )

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Decision metrics aggregated from the audit trail visible to your identity — computed by the backend, never in the browser."
        actions={
          <>
            <div className="flex overflow-hidden rounded-lg ring-1 ring-inset ring-slate-300">
              {WINDOWS.map((days) => (
                <button
                  key={days}
                  type="button"
                  onClick={() => setWindowDays(days)}
                  className={`px-3 py-2 text-sm font-semibold transition ${
                    windowDays === days
                      ? 'bg-indigo-600 text-white'
                      : 'bg-white text-slate-600 hover:bg-slate-50'
                  }`}
                >
                  {days}d
                </button>
              ))}
            </div>
            <Button variant="secondary" onClick={reload}>
              Refresh
            </Button>
          </>
        }
      />

      {loading ? <LoadingState label="Loading dashboard metrics…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}

      {data ? (
        <div className="space-y-6">
          <Callout tone="info">
            <span className="font-semibold">Visibility:</span>{' '}
            {scopeLabel(data.scope)} — window: last {data.window_days} days.
            Counts come from recorded audit events only.
          </Callout>

          {data.summary.total_requests === 0 ? (
            <EmptyState
              title="No privacy decisions recorded yet"
              description="Once a governed request is made, this dashboard will show real counts, charts, and recent decisions."
              action={
                <Link to="/simulator">
                  <Button>Open the Privacy Simulator</Button>
                </Link>
              }
            />
          ) : (
            <>
              <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <StatCard label="Total requests" value={data.summary.total_requests} />
                <StatCard
                  label="Allowed"
                  value={data.summary.decisions.ALLOW ?? 0}
                  tone="success"
                  hint={
                    (data.summary.decisions.PARTIAL_ALLOW ?? 0) > 0
                      ? `${data.summary.decisions.PARTIAL_ALLOW} partial allow with transformed fields`
                      : undefined
                  }
                />
                <StatCard
                  label="Blocked"
                  value={data.summary.decisions.BLOCK ?? 0}
                  tone="danger"
                  hint={
                    (data.summary.decisions.ESCALATION_NEEDED ?? 0) > 0
                      ? `${data.summary.decisions.ESCALATION_NEEDED} escalated for review`
                      : undefined
                  }
                />
                <StatCard
                  label="With transformations"
                  value={data.summary.requests_with_transformations}
                  tone="warning"
                  hint="requests where at least one field was masked, tokenized, or generalized"
                />
              </div>

              <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
                <Card className="px-5 py-5">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Model invocations
                  </p>
                  <p className="mt-2 text-2xl font-bold text-slate-900">
                    {data.summary.model_invocations}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    LLM calls that actually reached a provider
                  </p>
                </Card>
                <Card className="px-5 py-5">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Output-guard triggers
                  </p>
                  <p className="mt-2 text-2xl font-bold text-slate-900">
                    {data.summary.guard_triggered}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    model outputs flagged by the privacy guard
                  </p>
                </Card>
                <Card className="px-5 py-5">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Mosaic warnings
                  </p>
                  <p className="mt-2 text-2xl font-bold text-slate-900">
                    {data.summary.mosaic_warnings}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    decisions flagged for potential re-identification risk
                  </p>
                </Card>
              </div>

              <Card className="px-5 py-5">
                <div className="mb-4 flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-slate-900">
                    Decisions per day
                  </h2>
                  <span className="text-xs text-slate-500">
                    stacked by overall decision
                  </span>
                </div>
                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={data.daily.map((point) => ({
                        date: chartDate(point.date),
                        Allow: point.allow,
                        'Partial allow': point.partial_allow,
                        Block: point.block,
                        Escalation: point.escalation,
                      }))}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                      <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                      <Tooltip />
                      <Legend />
                      <Bar dataKey="Allow" stackId="a" fill="#10b981" />
                      <Bar dataKey="Partial allow" stackId="a" fill="#f59e0b" />
                      <Bar dataKey="Block" stackId="a" fill="#e11d48" />
                      <Bar dataKey="Escalation" stackId="a" fill="#0ea5e9" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </Card>

              <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
                <Card className="xl:col-span-2">
                  <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
                    <h2 className="text-sm font-semibold text-slate-900">
                      Recent privacy decisions
                    </h2>
                    <Link
                      to="/audit"
                      className="text-xs font-semibold text-indigo-600 hover:text-indigo-500"
                    >
                      Open audit trail →
                    </Link>
                  </div>
                  {data.recent_decisions.length ? (
                    <div className="overflow-x-auto">
                      <table className="min-w-full divide-y divide-slate-200 text-sm">
                        <thead>
                          <tr className="text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                            <th className="px-5 py-3">Time</th>
                            <th className="px-5 py-3">Decision</th>
                            <th className="px-5 py-3">Actor</th>
                            <th className="px-5 py-3">Resource</th>
                            <th className="px-5 py-3">Reasons</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {data.recent_decisions.map((item) => (
                            <tr key={item.id} className="hover:bg-slate-50">
                              <td className="whitespace-nowrap px-5 py-3 text-xs text-slate-600">
                                <Link
                                  to={`/audit/${item.id}`}
                                  className="font-medium text-indigo-600 hover:text-indigo-500"
                                >
                                  {formatDateTime(item.timestamp)}
                                </Link>
                              </td>
                              <td className="px-5 py-3">
                                <DecisionBadge decision={item.overall_decision} />
                              </td>
                              <td className="px-5 py-3">
                                <span className="text-slate-800">
                                  {item.actor.name ?? item.actor.id ?? '—'}
                                </span>
                                <span className="ml-2 text-xs text-slate-400">
                                  {item.actor.kind}
                                </span>
                              </td>
                              <td className="px-5 py-3 font-mono text-xs text-slate-600">
                                {item.resource ?? '—'}
                                {item.resource_id ? ` · ${item.resource_id}` : ''}
                              </td>
                              <td className="px-5 py-3">
                                {item.reason_codes.length ? (
                                  <span className="flex flex-wrap gap-1">
                                    {item.reason_codes.slice(0, 3).map((code, index) => (
                                      <Badge
                                        key={`${code}-${index}`}
                                        value={code}
                                        classes="bg-slate-100 text-slate-600 ring-slate-200"
                                      />
                                    ))}
                                  </span>
                                ) : (
                                  <span className="text-slate-400">—</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="px-5 py-6 text-sm text-slate-500">
                      No decisions visible in this window.
                    </p>
                  )}
                </Card>

                <div className="space-y-5">
                  <Card className="px-5 py-5">
                    <h2 className="text-sm font-semibold text-slate-900">
                      Provider health
                    </h2>
                    <dl className="mt-3 space-y-3 text-sm">
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">Database</dt>
                        <dd className="flex items-center gap-2">
                          <StatusBadge
                            status={
                              data.health.database === 'healthy'
                                ? 'healthy'
                                : 'unhealthy'
                            }
                          />
                          {typeof data.health.database_latency_ms === 'number' ? (
                            <span className="text-xs text-slate-500">
                              {data.health.database_latency_ms} ms
                            </span>
                          ) : null}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">LLM provider</dt>
                        <dd className="text-right">
                          <span className="font-medium text-slate-800">
                            {data.health.llm.provider ?? '—'}
                          </span>
                          {data.health.llm.model ? (
                            <span className="block text-xs text-slate-500">
                              {data.health.llm.model}
                            </span>
                          ) : null}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">Classifier</dt>
                        <dd>
                          <StatusBadge
                            status={String(
                              data.health.classifier.status ?? 'unknown',
                            ).toUpperCase()}
                          />
                        </dd>
                      </div>
                    </dl>
                    <Link
                      to="/system"
                      className="mt-4 inline-block text-xs font-semibold text-indigo-600 hover:text-indigo-500"
                    >
                      System status →
                    </Link>
                  </Card>

                  <Card className="px-5 py-5">
                    <h2 className="text-sm font-semibold text-slate-900">
                      Policy configuration
                    </h2>
                    <p className="mt-3 text-3xl font-bold text-slate-900">
                      {data.policy_stats.active_policies}
                    </p>
                    <p className="text-xs text-slate-500">active policies</p>
                    {data.policy_stats.most_triggered_policy ? (
                      <p className="mt-3 text-sm text-slate-600">
                        Most cited in decisions:{' '}
                        <span className="font-mono text-xs text-slate-800">
                          {data.policy_stats.most_triggered_policy}
                        </span>
                      </p>
                    ) : null}
                    <Link
                      to="/policies"
                      className="mt-4 inline-block text-xs font-semibold text-indigo-600 hover:text-indigo-500"
                    >
                      View policies →
                    </Link>
                  </Card>
                </div>
              </div>
            </>
          )}
        </div>
      ) : null}
    </div>
  )
}
