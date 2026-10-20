/**
 * Data Assets & Classifications.
 *
 * Classification metadata only: field names, types, sensitivity levels,
 * PII categories, and record counts. The endpoint never returns row data,
 * so raw values cannot appear on this page.
 */

import { useState } from 'react'

import { SensitivityBadge } from '../components/Badges'
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
} from '../components/ui'
import { listAssets } from '../lib/api/assets'
import { useApiResource } from '../lib/useApi'

const PAGE_SIZE = 10
const SENSITIVITY_LEVELS = ['low', 'medium', 'high', 'restricted']

export default function AssetsPage() {
  const [sensitivity, setSensitivity] = useState('')
  const [offset, setOffset] = useState(0)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const { data, loading, error, reload } = useApiResource(
    () =>
      listAssets({
        limit: PAGE_SIZE,
        offset,
        sensitivity: sensitivity || undefined,
      }),
    [sensitivity, offset],
  )

  function toggleExpanded(assetId: string) {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(assetId)) next.delete(assetId)
      else next.add(assetId)
      return next
    })
  }

  return (
    <div>
      <PageHeader
        title="Data Assets & Classifications"
        description="Catalog resources guarded by the gateway, with the field-level classifications the policy engine relies on."
        actions={
          <Button variant="secondary" onClick={reload}>
            Refresh
          </Button>
        }
      />

      <Card className="mb-6 px-5 py-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Sensitivity filter" hint="Show assets with at least one field at this level.">
            <Select
              value={sensitivity}
              onChange={(event) => {
                setSensitivity(event.target.value)
                setOffset(0)
              }}
            >
              <option value="">All levels</option>
              {SENSITIVITY_LEVELS.map((level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      </Card>

      {loading ? <LoadingState label="Loading the catalogue…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}

      {data && !loading && !error ? (
        data.items.length ? (
          <div className="space-y-4">
            {data.items.map((asset) => {
              const isOpen = expanded.has(asset.id)
              return (
                <Card key={asset.id}>
                  <button
                    type="button"
                    onClick={() => toggleExpanded(asset.id)}
                    className="flex w-full items-start justify-between gap-4 px-5 py-4 text-left"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="font-mono text-sm font-semibold text-slate-900">
                          {asset.name}
                        </h2>
                        <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600">
                          {asset.asset_type}
                        </span>
                        {asset.owner_department ? (
                          <span className="text-[11px] text-slate-400">
                            {asset.owner_department}
                          </span>
                        ) : null}
                      </div>
                      {asset.description ? (
                        <p className="mt-1 text-sm text-slate-600">
                          {asset.description}
                        </p>
                      ) : null}
                      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                        <span>
                          {asset.field_count} fields ·{' '}
                          {asset.record_count ?? '—'} records
                        </span>
                        <span className="flex flex-wrap gap-1">
                          {SENSITIVITY_LEVELS.map((level) =>
                            asset.sensitivity_summary[level] ? (
                              <SensitivityBadge
                                key={level}
                                level={`${asset.sensitivity_summary[level]} ${level}`}
                              />
                            ) : null,
                          )}
                        </span>
                      </div>
                    </div>
                    <span className="mt-1 shrink-0 text-slate-400" aria-hidden="true">
                      {isOpen ? '▲' : '▼'}
                    </span>
                  </button>

                  {isOpen ? (
                    <div className="border-t border-slate-200">
                      <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-slate-200 text-sm">
                          <thead>
                            <tr className="text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                              <th className="px-5 py-3">Field</th>
                              <th className="px-5 py-3">Column</th>
                              <th className="px-5 py-3">Type</th>
                              <th className="px-5 py-3">Sensitivity</th>
                              <th className="px-5 py-3">PII category</th>
                              <th className="px-5 py-3">Description</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {asset.fields.map((field) => (
                              <tr key={field.name}>
                                <td className="px-5 py-3 font-mono text-xs text-slate-800">
                                  {field.name}
                                </td>
                                <td className="px-5 py-3 font-mono text-xs text-slate-500">
                                  {field.column_name ?? '—'}
                                </td>
                                <td className="px-5 py-3 text-xs text-slate-600">
                                  {field.field_type}
                                </td>
                                <td className="px-5 py-3">
                                  <SensitivityBadge level={field.sensitivity} />
                                </td>
                                <td className="px-5 py-3 text-xs text-slate-600">
                                  {field.pii_category ?? '—'}
                                </td>
                                <td className="px-5 py-3 text-xs text-slate-600">
                                  {field.description ?? '—'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : null}
                </Card>
              )
            })}
            <Card>
              <Pagination pagination={data.pagination} onOffsetChange={setOffset} />
            </Card>
          </div>
        ) : (
          <EmptyState
            title="No assets match the filter"
            description="Try a different sensitivity level."
          />
        )
      ) : null}

      {data && !loading && !error ? (
        <div className="mt-4">
          <Callout tone="info">
            This catalogue exposes classification metadata only — names,
            types and sensitivity annotations. No record values are ever
            returned by this endpoint.
          </Callout>
        </div>
      ) : null}
    </div>
  )
}
