/**
 * Privacy Request Simulator.
 *
 * Builds a real request for `POST /api/v1/privacy/secure-request` and
 * renders exactly what the gateway returned: the overall decision, reason
 * codes, per-field actions with already-transformed values, model usage,
 * and the audit reference. Values that the backend did not authorise are
 * never requested, never received, and never displayed.
 */

import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'

import {
  ActionBadge,
  Badge,
  DecisionBadge,
} from '../components/Badges'
import {
  Button,
  Callout,
  Card,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  Select,
  TextArea,
  TextInput,
} from '../components/ui'
import { describeError } from '../lib/api/errors'
import { listAssets } from '../lib/api/assets'
import { secureRequest } from '../lib/api/privacy'
import type {
  DataAssetItem,
  SecureRequestPayload,
  SecureRequestResult,
} from '../lib/api/types'
import { formatDateTime, prettyJson, prettyValue } from '../lib/format'
import { KNOWN_PURPOSES, SIMULATOR_SCENARIOS } from '../lib/scenarios'
import { useApiResource } from '../lib/useApi'

function newSessionId(): string {
  const random = Math.random().toString(36).slice(2, 10)
  return `ui-${Date.now().toString(36)}-${random}`
}

const TARGET_SUGGESTIONS = [
  'EMP001',
  'EMP002',
  'EMP003',
  'ORD0001',
  'ORD0002',
  'CUS001',
  'CUS002',
  'CUS003',
]

function decisionBannerClasses(decision: string): string {
  switch (decision) {
    case 'ALLOW':
      return 'border-emerald-300 bg-emerald-50'
    case 'PARTIAL_ALLOW':
      return 'border-amber-300 bg-amber-50'
    case 'BLOCK':
      return 'border-rose-300 bg-rose-50'
    case 'ESCALATION_NEEDED':
      return 'border-sky-300 bg-sky-50'
    default:
      return 'border-slate-300 bg-slate-50'
  }
}

export default function SimulatorPage() {
  const assets = useApiResource(() => listAssets({ limit: 100 }), [])

  const [resource, setResource] = useState('employee_salary')
  const [selectedFields, setSelectedFields] = useState<string[]>([
    'employee_id',
    'base_salary',
  ])
  const [purpose, setPurpose] = useState('hr_review')
  const [operation, setOperation] = useState<'read' | 'aggregate'>('read')
  const [targetEntity, setTargetEntity] = useState('EMP001')
  const [purposeDetail, setPurposeDetail] = useState('')
  const [sessionId, setSessionId] = useState(() => newSessionId())
  const [includeLlm, setIncludeLlm] = useState(false)

  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [result, setResult] = useState<SecureRequestResult | null>(null)
  const [lastPayload, setLastPayload] = useState<SecureRequestPayload | null>(null)
  const [activeScenario, setActiveScenario] = useState<string | null>(null)
  const [showRequestJson, setShowRequestJson] = useState(false)
  const [showResponseJson, setShowResponseJson] = useState(false)

  const assetList: DataAssetItem[] = useMemo(
    () => assets.data?.items ?? [],
    [assets.data],
  )
  const selectedAsset = assetList.find((asset) => asset.name === resource)

  // Keep the resource selection valid once the catalogue loads.
  useEffect(() => {
    if (!assetList.length) return
    if (!assetList.some((asset) => asset.name === resource)) {
      setResource(assetList[0].name)
    }
  }, [assetList, resource])

  // Selecting a resource clears fields that do not belong to it.
  useEffect(() => {
    if (!selectedAsset) return
    const names = new Set(selectedAsset.fields.map((field) => field.name))
    setSelectedFields((current) => current.filter((name) => names.has(name)))
  }, [selectedAsset])

  function applyScenario(scenarioId: string) {
    const scenario = SIMULATOR_SCENARIOS.find((item) => item.id === scenarioId)
    if (!scenario) return
    const payload = scenario.payload
    setResource(payload.resource)
    setSelectedFields([...payload.data_fields])
    setPurpose(payload.purpose)
    setOperation(payload.operation ?? 'read')
    setTargetEntity(payload.target_entity ?? '')
    setPurposeDetail(payload.purpose_detail ?? '')
    setIncludeLlm(false)
    setSessionId(newSessionId())
    setActiveScenario(scenario.id)
    setResult(null)
    setSubmitError(null)
  }

  function toggleField(name: string) {
    setSelectedFields((current) =>
      current.includes(name)
        ? current.filter((field) => field !== name)
        : [...current, name],
    )
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (submitting) return
    if (!resource || selectedFields.length === 0) {
      setSubmitError('Choose a resource and at least one field.')
      return
    }
    const payload: SecureRequestPayload = {
      resource,
      data_fields: selectedFields,
      purpose,
      operation,
      target_entity: targetEntity.trim() || null,
      purpose_detail: purposeDetail.trim() || null,
      context: { session_id: sessionId },
      include_llm_response: includeLlm,
    }
    setSubmitting(true)
    setSubmitError(null)
    setLastPayload(payload)
    try {
      const response = await secureRequest(payload)
      setResult(response)
    } catch (cause) {
      setResult(null)
      setSubmitError(describeError(cause))
    } finally {
      setSubmitting(false)
    }
  }

  const recordColumns = useMemo(() => {
    if (!result?.records?.length) return []
    const keys = new Set<string>()
    for (const record of result.records) {
      for (const key of Object.keys(record)) keys.add(key)
    }
    return [...keys]
  }, [result])

  return (
    <div>
      <PageHeader
        title="Privacy Request Simulator"
        description="Send a real governed request. The decision, transformations, and audit entry are produced by the gateway — outcomes depend on the identity you signed in with."
      />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Left column: scenarios + form */}
        <div className="space-y-6">
          <Card className="px-5 py-5">
            <h2 className="text-sm font-semibold text-slate-900">
              Demo scenarios
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              Presets from the seeded catalogue. Expected outcomes are
              documentation — the actual decision is always the backend's.
            </p>
            <div className="mt-4 space-y-2">
              {SIMULATOR_SCENARIOS.map((scenario) => (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => applyScenario(scenario.id)}
                  className={`w-full rounded-xl border px-4 py-3 text-left transition ${
                    activeScenario === scenario.id
                      ? 'border-indigo-400 bg-indigo-50'
                      : 'border-slate-200 bg-white hover:border-indigo-300 hover:bg-indigo-50/40'
                  }`}
                >
                  <span className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-800">
                      {scenario.title}
                    </span>
                    <span className="rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
                      {scenario.expected}
                    </span>
                  </span>
                  <span className="mt-1 block text-xs text-slate-500">
                    {scenario.description}
                  </span>
                  <span className="mt-1 block text-[11px] text-slate-400">
                    best demoed as {scenario.bestDemoedAs}
                  </span>
                </button>
              ))}
            </div>
          </Card>

          <Card className="px-5 py-5">
            <h2 className="text-sm font-semibold text-slate-900">
              Request builder
            </h2>
            {assets.loading ? (
              <div className="mt-4">
                <LoadingState label="Loading the data catalogue…" />
              </div>
            ) : assets.error ? (
              <div className="mt-4">
                <ErrorState message={assets.error} onRetry={assets.reload} />
              </div>
            ) : (
              <form onSubmit={(event) => void handleSubmit(event)} className="mt-4 space-y-4">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label="Resource">
                    <Select
                      value={resource}
                      onChange={(event) => setResource(event.target.value)}
                    >
                      {assetList.map((asset) => (
                        <option key={asset.name} value={asset.name}>
                          {asset.name}
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field label="Operation">
                    <Select
                      value={operation}
                      onChange={(event) =>
                        setOperation(event.target.value as 'read' | 'aggregate')
                      }
                    >
                      <option value="read">read</option>
                      <option value="aggregate">aggregate</option>
                    </Select>
                  </Field>
                  <Field label="Purpose">
                    <Select
                      value={purpose}
                      onChange={(event) => setPurpose(event.target.value)}
                    >
                      {KNOWN_PURPOSES.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field
                    label="Target entity"
                    hint="Record the request is about (optional for aggregate)."
                  >
                    <TextInput
                      value={targetEntity}
                      onChange={(event) => setTargetEntity(event.target.value)}
                      list="target-suggestions"
                      placeholder="e.g. EMP001"
                    />
                    <datalist id="target-suggestions">
                      {TARGET_SUGGESTIONS.map((value) => (
                        <option key={value} value={value} />
                      ))}
                    </datalist>
                  </Field>
                </div>

                <div>
                  <span className="mb-1 block text-sm font-medium text-slate-700">
                    Data fields
                    {selectedAsset ? (
                      <span className="ml-2 text-xs font-normal text-slate-500">
                        {selectedAsset.field_count} fields ·{' '}
                        {selectedAsset.record_count ?? '—'} records
                      </span>
                    ) : null}
                  </span>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {(selectedAsset?.fields ?? []).map((field) => (
                      <label
                        key={field.name}
                        className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
                          selectedFields.includes(field.name)
                            ? 'border-indigo-300 bg-indigo-50/60'
                            : 'border-slate-200 bg-white hover:bg-slate-50'
                        }`}
                      >
                        <input
                          type="checkbox"
                          className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
                          checked={selectedFields.includes(field.name)}
                          onChange={() => toggleField(field.name)}
                        />
                        <span className="min-w-0">
                          <span className="flex flex-wrap items-center gap-1.5">
                            <span className="font-mono text-xs text-slate-800">
                              {field.name}
                            </span>
                            <Badge
                              value={field.sensitivity}
                              classes={
                                field.sensitivity === 'restricted'
                                  ? 'bg-rose-50 text-rose-700 ring-rose-200'
                                  : field.sensitivity === 'high'
                                    ? 'bg-amber-50 text-amber-700 ring-amber-200'
                                    : 'bg-slate-100 text-slate-600 ring-slate-200'
                              }
                            />
                            {field.pii_category ? (
                              <span className="text-[11px] text-slate-400">
                                {field.pii_category}
                              </span>
                            ) : null}
                          </span>
                          {field.description ? (
                            <span className="mt-0.5 block text-[11px] text-slate-500">
                              {field.description}
                            </span>
                          ) : null}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                <Field
                  label="Purpose detail (free text, optional)"
                  hint="Inspected server-side for manipulation attempts."
                >
                  <TextArea
                    rows={2}
                    value={purposeDetail}
                    onChange={(event) => setPurposeDetail(event.target.value)}
                    placeholder="e.g. resolving ticket #4821"
                  />
                </Field>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label="Session id" hint="Correlation id for the audit trail.">
                    <TextInput
                      value={sessionId}
                      onChange={(event) => setSessionId(event.target.value)}
                    />
                  </Field>
                  <label className="flex items-end gap-2 pb-2">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
                      checked={includeLlm}
                      onChange={(event) => setIncludeLlm(event.target.checked)}
                    />
                    <span className="text-sm text-slate-700">
                      Include a model response (goes through the safe context
                      builder + output guard)
                    </span>
                  </label>
                </div>

                {submitError ? (
                  <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700">
                    {submitError}
                  </div>
                ) : null}

                <div className="flex flex-wrap items-center gap-3">
                  <Button type="submit" disabled={submitting}>
                    {submitting ? 'Sending to gateway…' : 'Send secure request'}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => {
                      setSessionId(newSessionId())
                      setActiveScenario(null)
                    }}
                  >
                    New session id
                  </Button>
                  <button
                    type="button"
                    onClick={() => setShowRequestJson((value) => !value)}
                    className="text-xs font-semibold text-slate-500 underline-offset-2 hover:text-slate-700 hover:underline"
                  >
                    {showRequestJson ? 'Hide request JSON' : 'View request JSON'}
                  </button>
                </div>

                {showRequestJson ? (
                  <pre className="max-h-64 overflow-auto rounded-lg bg-slate-900 px-4 py-3 font-mono text-xs leading-relaxed text-slate-100">
                    {prettyJson(
                      lastPayload ?? {
                        resource,
                        data_fields: selectedFields,
                        purpose,
                        operation,
                        target_entity: targetEntity || null,
                        context: { session_id: sessionId },
                        include_llm_response: includeLlm,
                      },
                    )}
                  </pre>
                ) : null}
              </form>
            )}
          </Card>
        </div>

        {/* Right column: result */}
        <div className="space-y-6">
          {!result && !submitting ? (
            <Card className="px-6 py-10 text-center">
              <p className="text-sm font-semibold text-slate-700">
                No request sent yet
              </p>
              <p className="mx-auto mt-1 max-w-sm text-sm text-slate-500">
                Pick a scenario or build a request manually, then send it. The
                gateway response — including blocks and transformations — will
                appear here.
              </p>
            </Card>
          ) : null}

          {submitting ? <LoadingState label="The gateway is evaluating the request…" /> : null}

          {result ? (
            <>
              <div
                data-testid="result-banner"
                className={`rounded-xl border px-5 py-5 ${decisionBannerClasses(result.overall_decision)}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <DecisionBadge decision={result.overall_decision} />
                    <p className="mt-2 font-mono text-xs text-slate-700">
                      {result.reason_code ?? '—'}
                    </p>
                    {result.reason ? (
                      <p className="mt-1 text-sm text-slate-600">
                        {result.reason}
                      </p>
                    ) : null}
                  </div>
                  <div className="text-right text-xs text-slate-500">
                    <p>{formatDateTime(result.timestamp)}</p>
                    <p className="mt-1">
                      retrieved:{' '}
                      <span className="font-semibold">
                        {result.retrieved ? 'yes' : 'no'}
                      </span>
                    </p>
                  </div>
                </div>
                <dl className="mt-4 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                  <div>
                    <dt className="font-semibold uppercase tracking-wide text-slate-500">
                      Request id
                    </dt>
                    <dd className="mt-0.5 break-all font-mono text-slate-700">
                      {result.request_id}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-semibold uppercase tracking-wide text-slate-500">
                      Audit reference
                    </dt>
                    <dd className="mt-0.5 break-all font-mono text-slate-700">
                      {result.audit_id ? (
                        <Link
                          to={`/audit/${result.audit_id}`}
                          className="text-indigo-600 hover:text-indigo-500"
                        >
                          {result.audit_id}
                        </Link>
                      ) : (
                        '—'
                      )}
                    </dd>
                  </div>
                </dl>
                {result.guard_triggered || result.mosaic_warning ? (
                  <div className="mt-3 flex flex-wrap gap-2 text-xs font-semibold">
                    {result.guard_triggered ? (
                      <span className="rounded-md bg-rose-100 px-2 py-1 text-rose-700">
                        output guard triggered
                      </span>
                    ) : null}
                    {result.mosaic_warning ? (
                      <span className="rounded-md bg-amber-100 px-2 py-1 text-amber-700">
                        mosaic warning
                      </span>
                    ) : null}
                  </div>
                ) : null}
              </div>

              <Card>
                <div className="border-b border-slate-200 px-5 py-4">
                  <h2 className="text-sm font-semibold text-slate-900">
                    Field decisions
                  </h2>
                  <p className="mt-0.5 text-xs text-slate-500">
                    Values below are exactly what the gateway released —
                    already masked/tokenized/generalized where the policy
                    required it.
                  </p>
                </div>
                {Object.keys(result.fields).length ? (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-slate-200 text-sm">
                      <thead>
                        <tr className="text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                          <th className="px-5 py-3">Field</th>
                          <th className="px-5 py-3">Action</th>
                          <th className="px-5 py-3">Released value</th>
                          <th className="px-5 py-3">Reason</th>
                          <th className="px-5 py-3">Policy</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {Object.entries(result.fields).map(([name, decision]) => (
                          <tr key={name}>
                            <td className="px-5 py-3 font-mono text-xs text-slate-800">
                              {name}
                            </td>
                            <td className="px-5 py-3">
                              <ActionBadge action={decision.action} />
                            </td>
                            <td className="max-w-[16rem] truncate px-5 py-3 font-mono text-xs text-slate-700">
                              {prettyValue(decision.value)}
                            </td>
                            <td className="px-5 py-3 font-mono text-xs text-slate-500">
                              {decision.reason_code ?? '—'}
                            </td>
                            <td className="px-5 py-3 font-mono text-xs text-slate-500">
                              {decision.policy_id
                                ? `${decision.policy_id}@v${decision.policy_version ?? '—'}`
                                : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="px-5 py-5 text-sm text-slate-500">
                    No field-level entries in the response.
                  </p>
                )}
              </Card>

              {result.records?.length ? (
                <Card>
                  <div className="border-b border-slate-200 px-5 py-4">
                    <h2 className="text-sm font-semibold text-slate-900">
                      Authorized records ({result.records.length})
                    </h2>
                    <p className="mt-0.5 text-xs text-slate-500">
                      Only the fields the policy released; transformed values
                      appear as released.
                    </p>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-slate-200 text-sm">
                      <thead>
                        <tr className="text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                          {recordColumns.map((column) => (
                            <th key={column} className="px-5 py-3">
                              {column}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {result.records.map((record, index) => (
                          <tr key={index}>
                            {recordColumns.map((column) => (
                              <td
                                key={column}
                                className="max-w-[16rem] truncate px-5 py-3 font-mono text-xs text-slate-700"
                              >
                                {prettyValue(record[column])}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              ) : null}

              {result.llm ? (
                <Card className="px-5 py-5">
                  <h2 className="text-sm font-semibold text-slate-900">
                    Model usage
                  </h2>
                  <dl className="mt-3 grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        Requested
                      </dt>
                      <dd className="text-slate-800">
                        {result.llm.requested ? 'yes' : 'no'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        Invoked
                      </dt>
                      <dd className="text-slate-800">
                        {result.llm.invoked ? 'yes' : 'no'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        Provider / model
                      </dt>
                      <dd className="font-mono text-xs text-slate-700">
                        {result.llm.provider ?? '—'}
                        {result.llm.model ? ` / ${result.llm.model}` : ''}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        Guard
                      </dt>
                      <dd className="text-slate-800">
                        {result.llm.guard
                          ? result.llm.guard.triggered
                            ? `triggered (${result.llm.guard.action})`
                            : `passed (${result.llm.guard.action})`
                          : '—'}
                      </dd>
                    </div>
                  </dl>
                  {result.llm.error ? (
                    <p className="mt-3 rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700">
                      {result.llm.error_code ?? 'ERROR'}: {result.llm.error}
                    </p>
                  ) : null}
                  {result.llm_response ? (
                    <div className="mt-4">
                      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        Model response (post-guard)
                      </p>
                      <p className="mt-1 whitespace-pre-wrap rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-700">
                        {result.llm_response}
                      </p>
                    </div>
                  ) : null}
                  {result.llm.guard?.findings.length ? (
                    <div className="mt-4">
                      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        Guard findings (metadata only — matched text is never
                        returned)
                      </p>
                      <ul className="mt-1 space-y-1">
                        {result.llm.guard.findings.map((finding, index) => (
                          <li
                            key={index}
                            className="rounded-lg bg-slate-50 px-3 py-2 font-mono text-xs text-slate-600"
                          >
                            {finding.category ?? 'finding'}
                            {finding.rule ? ` · ${finding.rule}` : ''} ·{' '}
                            {finding.permitted ? 'permitted' : 'blocked'}
                            {finding.redacted_as
                              ? ` · redacted as ${finding.redacted_as}`
                              : ''}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </Card>
              ) : null}

              <Card className="px-5 py-4">
                <button
                  type="button"
                  onClick={() => setShowResponseJson((value) => !value)}
                  className="text-xs font-semibold text-slate-500 underline-offset-2 hover:text-slate-700 hover:underline"
                >
                  {showResponseJson
                    ? 'Hide raw gateway response'
                    : 'View raw gateway response'}
                </button>
                {showResponseJson ? (
                  <pre className="mt-3 max-h-96 overflow-auto rounded-lg bg-slate-900 px-4 py-3 font-mono text-xs leading-relaxed text-slate-100">
                    {prettyJson(result)}
                  </pre>
                ) : null}
              </Card>
            </>
          ) : null}

          <Callout tone="info" title="What you are seeing">
            The browser asked the gateway; the gateway decided. No policy
            logic, role check, or redaction happens in this page — if the
            backend blocks a field, the blocked value never reaches the
            browser.
          </Callout>
        </div>
      </div>
    </div>
  )
}
