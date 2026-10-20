/**
 * Renders the full explainability view of one audit event.
 *
 * Everything shown here is the gateway's allowlisted projection of the
 * stored event: identifiers, reason codes, policy versions, transformation
 * *types* and model metadata — never raw protected values, prompts, or
 * credentials.
 */

import type { AuditEventDetail } from '../lib/api/types'
import { formatDateTime, humanizeAction, prettyJson } from '../lib/format'
import {
  ActionBadge,
  DecisionBadge,
  OutcomeBadge,
  SensitivityBadge,
} from './Badges'
import { Card, Chips, KeyValue } from './ui'

export default function AuditEventDetailView({
  event,
}: {
  event: AuditEventDetail
}) {
  return (
    <div className="space-y-5">
      <Card className="px-5 py-5">
        <div className="flex flex-wrap items-center gap-2">
          <DecisionBadge decision={event.overall_decision} />
          <OutcomeBadge outcome={event.outcome} />
          <span className="font-mono text-xs text-slate-500">
            {humanizeAction(event.action)}
          </span>
        </div>
        <dl className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KeyValue label="Event id" mono>{event.id}</KeyValue>
          <KeyValue label="Timestamp">{formatDateTime(event.timestamp)}</KeyValue>
          <KeyValue label="Request id" mono>{event.request_id ?? '—'}</KeyValue>
          <KeyValue label="Session id" mono>{event.session_id ?? '—'}</KeyValue>
          <KeyValue label="Resource" mono>{event.resource ?? '—'}</KeyValue>
          <KeyValue label="Resource id" mono>{event.resource_id ?? '—'}</KeyValue>
          <KeyValue label="Operation">{event.operation ?? '—'}</KeyValue>
          <KeyValue label="Subject scope">{event.subject_scope ?? '—'}</KeyValue>
          <KeyValue label="Purpose">
            {event.purpose ?? '—'}
            {event.purpose_recognized === false ? (
              <span className="ml-2 text-xs font-semibold text-amber-600">
                not recognised
              </span>
            ) : null}
          </KeyValue>
          <KeyValue label="IP address" mono>{event.ip_address ?? '—'}</KeyValue>
        </dl>
        {event.flags.length ? (
          <div className="mt-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Context flags
            </p>
            <div className="mt-1">
              <Chips values={event.flags} />
            </div>
          </div>
        ) : null}
      </Card>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card className="px-5 py-5">
          <h2 className="text-sm font-semibold text-slate-900">Actor</h2>
          <dl className="mt-3 space-y-3">
            <KeyValue label="Kind">{event.actor.kind}</KeyValue>
            <KeyValue label="Name">{event.actor.name ?? '—'}</KeyValue>
            <KeyValue label="Id" mono>{event.actor.id ?? '—'}</KeyValue>
            <KeyValue label="Roles / scopes">
              {event.actor.roles.length || event.actor.scopes.length ? (
                <Chips
                  values={[
                    ...event.actor.roles.map((role) => `role:${role}`),
                    ...event.actor.scopes,
                  ]}
                />
              ) : (
                '—'
              )}
            </KeyValue>
          </dl>
        </Card>

        <Card className="px-5 py-5">
          <h2 className="text-sm font-semibold text-slate-900">Model usage</h2>
          <dl className="mt-3 space-y-3">
            <KeyValue label="Requested">
              {event.model_requested ? 'yes' : 'no'}
            </KeyValue>
            <KeyValue label="Invoked">
              {event.model_invoked ? 'yes' : 'no'}
            </KeyValue>
            <KeyValue label="Provider / model">
              {event.llm?.provider ?? '—'}
              {event.llm?.model ? ` / ${event.llm.model}` : ''}
            </KeyValue>
            <KeyValue label="Output guard">
              {event.llm?.guard_triggered ? (
                <span className="font-semibold text-rose-600">
                  triggered
                  {event.llm.guard_action ? ` (${event.llm.guard_action})` : ''}
                </span>
              ) : (
                'not triggered'
              )}
            </KeyValue>
            <KeyValue label="Guard reason" mono>
              {event.llm?.guard_reason_code ?? '—'}
            </KeyValue>
            <KeyValue label="Error code" mono>
              {event.llm?.error_code ?? '—'}
            </KeyValue>
          </dl>
        </Card>

        <Card className="px-5 py-5">
          <h2 className="text-sm font-semibold text-slate-900">Correlation</h2>
          {Object.keys(event.correlation).length ? (
            <dl className="mt-3 space-y-3">
              {Object.entries(event.correlation).map(([key, value]) => (
                <KeyValue key={key} label={key} mono>
                  {typeof value === 'string' || typeof value === 'number'
                    ? String(value)
                    : prettyJson(value)}
                </KeyValue>
              ))}
            </dl>
          ) : (
            <p className="mt-3 text-sm text-slate-500">No correlation metadata.</p>
          )}
          {event.mosaic_warning ? (
            <p className="mt-4 rounded-lg bg-amber-50 px-3 py-2 text-xs font-semibold text-amber-700 ring-1 ring-inset ring-amber-200">
              Mosaic warning recorded for this decision
            </p>
          ) : null}
        </Card>
      </div>

      <Card>
        <div className="border-b border-slate-200 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-900">
            Field decisions ({event.decisions.length})
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Reasons and policy versions per field — values themselves are never
            stored in the audit trail.
          </p>
        </div>
        {event.decisions.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead>
                <tr className="text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                  <th className="px-5 py-3">Field</th>
                  <th className="px-5 py-3">Action</th>
                  <th className="px-5 py-3">Reason code</th>
                  <th className="px-5 py-3">Policy</th>
                  <th className="px-5 py-3">Sensitivity</th>
                  <th className="px-5 py-3">PII category</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {event.decisions.map((entry, index) => (
                  <tr key={`${entry.field}-${index}`}>
                    <td className="px-5 py-3 font-mono text-xs text-slate-800">
                      {entry.field}
                    </td>
                    <td className="px-5 py-3">
                      <ActionBadge action={entry.action} />
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-600">
                      {entry.reason_code}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-600">
                      {entry.policy_id
                        ? `${entry.policy_id}@v${entry.policy_version ?? '—'}`
                        : '—'}
                    </td>
                    <td className="px-5 py-3">
                      {entry.sensitivity ? (
                        <SensitivityBadge level={entry.sensitivity} />
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="px-5 py-3 text-slate-600">
                      {entry.pii_category ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="px-5 py-6 text-sm text-slate-500">
            No per-field decisions recorded for this event.
          </p>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card className="px-5 py-5">
          <h2 className="text-sm font-semibold text-slate-900">
            Transformations ({event.transformations.length})
          </h2>
          {event.transformations.length ? (
            <ul className="mt-3 space-y-2">
              {event.transformations.map((entry, index) => (
                <li
                  key={`${entry.field}-${entry.transformation}-${index}`}
                  className="flex items-center justify-between gap-3 rounded-lg bg-slate-50 px-3 py-2"
                >
                  <span className="font-mono text-xs text-slate-700">
                    {entry.field}
                  </span>
                  <ActionBadge action={entry.transformation} />
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-slate-500">
              No transformations were applied.
            </p>
          )}
        </Card>

        <Card className="px-5 py-5">
          <h2 className="text-sm font-semibold text-slate-900">
            Requested fields ({event.requested_fields.length})
          </h2>
          {event.requested_fields.length ? (
            <div className="mt-3">
              <Chips values={event.requested_fields} />
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-500">None recorded.</p>
          )}
          <div className="mt-5 grid grid-cols-2 gap-4">
            <KeyValue label="Reason codes">
              <Chips values={event.reason_codes} />
            </KeyValue>
            <KeyValue label="Policy versions">
              <Chips
                values={event.policy_versions.map((version) => `v${version}`)}
              />
            </KeyValue>
            <KeyValue label="Sensitivity categories">
              <Chips values={event.sensitivity_categories} />
            </KeyValue>
            <KeyValue label="Guard outcome">
              {event.guard_outcome ?? '—'}
            </KeyValue>
          </div>
        </Card>
      </div>
    </div>
  )
}
