/**
 * Policy viewer — the rules currently in effect.
 *
 * Any authenticated principal may read active policies; inactive /
 * superseded versions require an administrator identity (the toggle is
 * only rendered for admins, and the backend enforces it regardless).
 */

import { useState } from 'react'
import type { FormEvent } from 'react'

import { useAuth } from '../auth/AuthContext'
import { Badge, StatusBadge, SensitivityBadge } from '../components/Badges'
import {
  Button,
  Callout,
  Card,
  Chips,
  EmptyState,
  ErrorState,
  Field,
  KeyValue,
  LoadingState,
  PageHeader,
  Pagination,
  TextInput,
} from '../components/ui'
import { listPolicies } from '../lib/api/policies'
import { formatDate } from '../lib/format'
import { useApiResource } from '../lib/useApi'

const PAGE_SIZE = 10

export default function PoliciesPage() {
  const { user } = useAuth()
  const isAdminHint = (user?.roles ?? []).some((role) => role.name === 'admin')

  const [resource, setResource] = useState('')
  const [role, setRole] = useState('')
  const [includeInactive, setIncludeInactive] = useState(false)
  const [applied, setApplied] = useState({ resource: '', role: '' })
  const [offset, setOffset] = useState(0)

  const { data, loading, error, reload } = useApiResource(
    () =>
      listPolicies({
        limit: PAGE_SIZE,
        offset,
        resource: applied.resource.trim() || undefined,
        role: applied.role.trim() || undefined,
        include_inactive: includeInactive || undefined,
      }),
    [applied, includeInactive, offset],
  )

  function apply(event: FormEvent) {
    event.preventDefault()
    setApplied({ resource, role })
    setOffset(0)
  }

  return (
    <div>
      <PageHeader
        title="Privacy Policies"
        description="Versioned norms enforced by the policy engine at every gateway decision. Active policies are readable by any signed-in principal."
        actions={
          <Button variant="secondary" onClick={reload}>
            Refresh
          </Button>
        }
      />

      <Card className="mb-6 px-5 py-4">
        <form onSubmit={apply} className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field
            label="Resource"
            hint="Engine-style matching: exact name or trailing-* pattern."
          >
            <TextInput
              value={resource}
              onChange={(event) => setResource(event.target.value)}
              placeholder="e.g. employee_salary"
            />
          </Field>
          <Field label="Required role">
            <TextInput
              value={role}
              onChange={(event) => setRole(event.target.value)}
              placeholder="e.g. hr_manager"
            />
          </Field>
          <div className="flex items-end gap-3">
            <Button type="submit">Apply</Button>
            {isAdminHint ? (
              <label className="flex items-center gap-2 pb-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
                  checked={includeInactive}
                  onChange={(event) => {
                    setIncludeInactive(event.target.checked)
                    setOffset(0)
                  }}
                />
                Include inactive versions
              </label>
            ) : null}
          </div>
        </form>
        {!isAdminHint ? (
          <p className="mt-2 text-xs text-slate-500">
            Inactive/superseded policy versions are administrator-only; the
            backend returns 403 for anyone else.
          </p>
        ) : null}
      </Card>

      {loading ? <LoadingState label="Loading policies…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}

      {data && !loading && !error ? (
        data.items.length ? (
          <div className="space-y-4">
            {data.items.map((policy) => (
              <Card key={policy.id} className="px-5 py-5">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base font-semibold text-slate-900">
                    {policy.name}
                  </h2>
                  <Badge
                    value={`v${policy.version}`}
                    classes="bg-slate-100 text-slate-600 ring-slate-200"
                  />
                  <StatusBadge status={policy.status} />
                  {policy.action ? (
                    <Badge
                      value={policy.action}
                      classes={
                        policy.action === 'BLOCK'
                          ? 'bg-rose-50 text-rose-700 ring-rose-200'
                          : policy.action === 'MASK'
                            ? 'bg-amber-50 text-amber-700 ring-amber-200'
                            : 'bg-emerald-50 text-emerald-700 ring-emerald-200'
                      }
                    />
                  ) : null}
                  <span className="ml-auto text-xs text-slate-400">
                    priority {policy.priority}
                  </span>
                </div>
                {policy.description ? (
                  <p className="mt-1 text-sm text-slate-600">
                    {policy.description}
                  </p>
                ) : null}

                <dl className="mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
                  <KeyValue label="Resource pattern" mono>
                    {policy.resource_pattern}
                  </KeyValue>
                  <KeyValue label="Required role">
                    {policy.required_role ?? '—'}
                  </KeyValue>
                  <KeyValue label="Min. sensitivity">
                    {policy.min_sensitivity ? (
                      <SensitivityBadge level={policy.min_sensitivity} />
                    ) : (
                      '—'
                    )}
                  </KeyValue>
                  <KeyValue label="Effective">
                    {formatDate(policy.effective_from)}
                    {policy.effective_until
                      ? ` → ${formatDate(policy.effective_until)}`
                      : ''}
                  </KeyValue>
                </dl>

                <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
                  <KeyValue label="Allowed purposes">
                    <Chips values={policy.allowed_purposes} />
                  </KeyValue>
                  <KeyValue label="Allowed actions">
                    <Chips values={policy.allowed_actions} />
                  </KeyValue>
                </div>

                <details className="mt-4">
                  <summary className="cursor-pointer text-xs font-semibold text-slate-500 hover:text-slate-700">
                    Rule text
                  </summary>
                  <p className="mt-2 whitespace-pre-wrap rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    {policy.policy_text}
                  </p>
                </details>
              </Card>
            ))}
            <Card>
              <Pagination pagination={data.pagination} onOffsetChange={setOffset} />
            </Card>
          </div>
        ) : (
          <EmptyState
            title="No policies match"
            description="Adjust the filters. Seeded demo policies are installed by the backend seed script."
          />
        )
      ) : null}

      {data && !loading && !error ? (
        <div className="mt-4">
          <Callout tone="info">
            Policy text is the human-readable rule summary shipped with the
            project documentation — the engine evaluates the structured
            fields above.
          </Callout>
        </div>
      ) : null}
    </div>
  )
}
