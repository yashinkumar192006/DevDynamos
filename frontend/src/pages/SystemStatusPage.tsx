/**
 * System Status — provider health as reported by the backend.
 *
 * Combines `GET /api/v1/health` and `GET /api/v1/system/status`. The
 * frontend reports what the backend says; where a provider is
 * unconfigured, that fact is displayed rather than masked.
 */

import { StatusBadge } from '../components/Badges'
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  LoadingState,
  PageHeader,
} from '../components/ui'
import { API_BASE_URL } from '../lib/api/client'
import { fetchHealth, fetchSystemStatus } from '../lib/api/system'
import { useApiResource } from '../lib/useApi'

export default function SystemStatusPage() {
  const { data, loading, error, reload } = useApiResource(
    async () => {
      const [health, status] = await Promise.all([
        fetchHealth(),
        fetchSystemStatus(),
      ])
      return { health, status }
    },
    [],
  )

  return (
    <div>
      <PageHeader
        title="System Status"
        description="Live provider health reported by the gateway. This page displays backend state — it does not probe anything itself."
        actions={
          <Button variant="secondary" onClick={reload}>
            Refresh
          </Button>
        }
      />

      <Card className="mb-6 px-5 py-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <KeyValue label="API base URL" mono>
            {API_BASE_URL}
          </KeyValue>
          <KeyValue label="Gateway liveness (/api/v1/health)">
            {data ? (
              <span className="flex items-center gap-2">
                <StatusBadge
                  status={data.health.status === 'ok' ? 'OK' : data.health.status}
                />
              </span>
            ) : (
              '—'
            )}
          </KeyValue>
        </div>
      </Card>

      {loading ? <LoadingState label="Contacting the gateway…" /> : null}
      {error ? (
        <ErrorState
          message={error}
          onRetry={reload}
          hint="If the gateway is down, the console fails closed — nothing is cached or faked in the browser."
        />
      ) : null}

      {data && !loading && !error ? (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          <Card className="px-5 py-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">Database</h2>
              <StatusBadge
                status={
                  data.status.providers.database === 'healthy'
                    ? 'healthy'
                    : 'unhealthy'
                }
              />
            </div>
            <p className="mt-3 break-words text-sm text-slate-600">
              {data.status.providers.database}
            </p>
          </Card>

          <Card className="px-5 py-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">
                LLM provider
              </h2>
              <StatusBadge
                status={data.status.providers.llm.configured ? 'READY' : 'DRAFT'}
              />
            </div>
            <dl className="mt-3 space-y-3">
              <KeyValue label="Provider" mono>
                {data.status.providers.llm.provider ?? '—'}
              </KeyValue>
              <KeyValue label="Model" mono>
                {data.status.providers.llm.model ?? '—'}
              </KeyValue>
              <KeyValue label="Configured">
                {data.status.providers.llm.configured ? 'yes' : 'no'}
              </KeyValue>
              {data.status.providers.llm.detail ? (
                <KeyValue label="Detail">
                  {data.status.providers.llm.detail}
                </KeyValue>
              ) : null}
            </dl>
          </Card>

          <Card className="px-5 py-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">
                Classifier
              </h2>
              <StatusBadge
                status={String(
                  data.status.providers.classifier.status ?? 'unknown',
                ).toUpperCase()}
              />
            </div>
            <dl className="mt-3 space-y-3">
              {Object.entries(data.status.providers.classifier).map(
                ([key, value]) => (
                  <KeyValue key={key} label={key}>
                    {typeof value === 'object'
                      ? JSON.stringify(value)
                      : String(value)}
                  </KeyValue>
                ),
              )}
            </dl>
          </Card>
        </div>
      ) : null}

      {data && !loading && !error ? (
        <div className="mt-4">
          <Callout tone="info">
            Provider status is read from server configuration only. Model API
            keys and backend secrets are never exposed to this console.
          </Callout>
        </div>
      ) : null}
    </div>
  )
}
