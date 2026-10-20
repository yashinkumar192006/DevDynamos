/**
 * Audit Events — visibility-scoped, filtered, paginated trail.
 *
 * The backend applies the caller's scope in SQL: administrators see the
 * full trail, compliance roles see privacy-pipeline events, everyone
 * else sees their own events. Out-of-scope filters are rejected (403);
 * this page surfaces that rather than hiding it.
 */

import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'
import { Badge, DecisionBadge, OutcomeBadge } from '../components/Badges'
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  Pagination,
  Select,
  TextInput,
} from '../components/ui'
import { listAuditEvents } from '../lib/api/audit'
import type { AuditEventsQuery } from '../lib/api/types'
import { formatDateTime, humanizeAction, scopeLabel } from '../lib/format'
import { useApiResource } from '../lib/useApi'

const ACTIONS = [
  'data_access',
  'data_denied',
  'ai_query',
  'output_inspection',
  'policy_evaluation',
  'transformation',
  'admin_action',
  'login',
  'logout',
]

const OUTCOMES = ['success', 'denied', 'escalated', 'failed', 'passed', 'flagged']

const PAGE_SIZE = 20

interface FilterState {
  action: string
  outcome: string
  resource: string
  sessionId: string
  requesterId: string
  startDate: string
  endDate: string
}

const EMPTY_FILTERS: FilterState = {
  action: '',
  outcome: '',
  resource: '',
  sessionId: '',
  requesterId: '',
  startDate: '',
  endDate: '',
}

function toIso(value: string): string | undefined {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

export default function AuditEventsPage() {
  const { user } = useAuth()
  const navigate = useNavigate()

  const [draft, setDraft] = useState<FilterState>(EMPTY_FILTERS)
  const [applied, setApplied] = useState<FilterState>(EMPTY_FILTERS)
  const [offset, setOffset] = useState(0)

  const roles = user?.roles.map((role) => role.name) ?? []
  const isAdminHint = roles.includes('admin')
  const isComplianceHint =
    isAdminHint || roles.includes('hr_manager') || roles.includes('executive')

  const query: AuditEventsQuery = useMemo(
    () => ({
      limit: PAGE_SIZE,
      offset,
      action: applied.action || undefined,
      outcome: applied.outcome || undefined,
      resource: applied.resource.trim() || undefined,
      session_id: applied.sessionId.trim() || undefined,
      requester_id: applied.requesterId.trim() || undefined,
      start_date: toIso(applied.startDate),
      end_date: toIso(applied.endDate),
    }),
    [applied, offset],
  )

  const { data, loading, error, reload } = useApiResource(
    () => listAuditEvents(query),
    [query],
  )

  function applyFilters(event: FormEvent) {
    event.preventDefault()
    setApplied(draft)
    setOffset(0)
  }

  function resetFilters() {
    setDraft(EMPTY_FILTERS)
    setApplied(EMPTY_FILTERS)
    setOffset(0)
  }

  return (
    <div>
      <PageHeader
        title="Audit Events"
        description={`Visibility: ${scopeLabel(
          isAdminHint ? 'full' : isComplianceHint ? 'privacy_trail' : 'own',
        )} (client-side hint — the server enforces your scope).`}
        actions={
          <Button variant="secondary" onClick={reload}>
            Refresh
          </Button>
        }
      />

      <Card className="mb-6 px-5 py-4">
        <form
          onSubmit={applyFilters}
          className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4"
        >
          <Field label="Action">
            <Select
              value={draft.action}
              onChange={(event) =>
                setDraft({ ...draft, action: event.target.value })
              }
            >
              <option value="">All actions</option>
              {ACTIONS.map((action) => (
                <option key={action} value={action}>
                  {action}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Outcome">
            <Select
              value={draft.outcome}
              onChange={(event) =>
                setDraft({ ...draft, outcome: event.target.value })
              }
            >
              <option value="">All outcomes</option>
              {OUTCOMES.map((outcome) => (
                <option key={outcome} value={outcome}>
                  {outcome}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Resource">
            <TextInput
              value={draft.resource}
              onChange={(event) =>
                setDraft({ ...draft, resource: event.target.value })
              }
              placeholder="e.g. employee_salary"
            />
          </Field>
          <Field label="Session id">
            <TextInput
              value={draft.sessionId}
              onChange={(event) =>
                setDraft({ ...draft, sessionId: event.target.value })
              }
              placeholder="e.g. demo-end-to-end-1"
            />
          </Field>
          {isAdminHint ? (
            <Field label="Requester id" hint="Administrators can filter by any actor id.">
              <TextInput
                value={draft.requesterId}
                onChange={(event) =>
                  setDraft({ ...draft, requesterId: event.target.value })
                }
                placeholder="user or service-account id"
              />
            </Field>
          ) : null}
          <Field label="From">
            <TextInput
              type="datetime-local"
              value={draft.startDate}
              onChange={(event) =>
                setDraft({ ...draft, startDate: event.target.value })
              }
            />
          </Field>
          <Field label="To">
            <TextInput
              type="datetime-local"
              value={draft.endDate}
              onChange={(event) =>
                setDraft({ ...draft, endDate: event.target.value })
              }
            />
          </Field>
          <div className="flex items-end gap-2">
            <Button type="submit">Apply filters</Button>
            <Button variant="secondary" onClick={resetFilters}>
              Reset
            </Button>
          </div>
        </form>
      </Card>

      {loading ? <LoadingState label="Loading audit events…" /> : null}
      {error ? (
        <ErrorState
          message={error}
          onRetry={reload}
          hint="Filters outside your visibility scope are rejected by the backend (403) — this is enforced server-side."
        />
      ) : null}

      {data && !loading && !error ? (
        data.items.length ? (
          <Card>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead>
                  <tr className="text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                    <th className="px-5 py-3">Time</th>
                    <th className="px-5 py-3">Action</th>
                    <th className="px-5 py-3">Decision</th>
                    <th className="px-5 py-3">Outcome</th>
                    <th className="px-5 py-3">Actor</th>
                    <th className="px-5 py-3">Resource</th>
                    <th className="px-5 py-3">Reasons / flags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {data.items.map((item) => (
                    <tr
                      key={item.id}
                      data-testid="audit-row"
                      className="cursor-pointer hover:bg-slate-50"
                      onClick={() => navigate(`/audit/${item.id}`)}
                    >
                      <td className="whitespace-nowrap px-5 py-3 text-xs text-slate-600">
                        {formatDateTime(item.timestamp)}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-slate-700">
                        {humanizeAction(item.action)}
                      </td>
                      <td className="px-5 py-3">
                        <DecisionBadge decision={item.overall_decision} />
                      </td>
                      <td className="px-5 py-3">
                        <OutcomeBadge outcome={item.outcome} />
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
                        <span className="flex flex-wrap gap-1">
                          {item.reason_codes.slice(0, 2).map((code, index) => (
                            <Badge
                              key={`${code}-${index}`}
                              value={code}
                              classes="bg-slate-100 text-slate-600 ring-slate-200"
                            />
                          ))}
                          {item.mosaic_warning ? (
                            <Badge
                              value="mosaic"
                              classes="bg-amber-50 text-amber-700 ring-amber-200"
                            />
                          ) : null}
                          {item.model_invoked ? (
                            <Badge
                              value="model"
                              classes="bg-indigo-50 text-indigo-700 ring-indigo-200"
                            />
                          ) : null}
                          {item.guard_outcome ? (
                            <Badge
                              value={`guard:${item.guard_outcome}`}
                              classes="bg-rose-50 text-rose-700 ring-rose-200"
                            />
                          ) : null}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination pagination={data.pagination} onOffsetChange={setOffset} />
          </Card>
        ) : (
          <EmptyState
            title="No audit events match"
            description="Adjust the filters, or exercise the gateway from the Privacy Simulator to record real events."
            action={
              <Link to="/simulator">
                <Button>Open the Privacy Simulator</Button>
              </Link>
            }
          />
        )
      ) : null}

      {data && !loading && !error ? (
        <div className="mt-4">
          <Callout tone="info">
            Events store identifiers, reason codes, policy versions, and
            transformation types — never raw protected values, prompts, or
            credentials.
          </Callout>
        </div>
      ) : null}
    </div>
  )
}
