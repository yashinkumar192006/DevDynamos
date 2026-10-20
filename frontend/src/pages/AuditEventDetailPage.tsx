/**
 * Audit event detail — full explainability for one recorded decision.
 *
 * A 404 from the API is rendered as "not found or outside your scope":
 * the backend does not disclose whether an out-of-scope event exists.
 */

import { Link, useParams } from 'react-router-dom'

import AuditEventDetailView from '../components/AuditEventDetailView'
import {
  Button,
  ErrorState,
  LoadingState,
  PageHeader,
} from '../components/ui'
import { getAuditEvent } from '../lib/api/audit'
import { useApiResource } from '../lib/useApi'

export default function AuditEventDetailPage() {
  const { id = '' } = useParams<{ id: string }>()
  const { data, loading, error, reload } = useApiResource(
    () => getAuditEvent(id),
    [id],
  )

  return (
    <div>
      <PageHeader
        title="Audit Event"
        description={
          <>
            <span className="font-mono text-xs">{id}</span>
          </>
        }
        actions={
          <Link to="/audit">
            <Button variant="secondary">← Back to audit trail</Button>
          </Link>
        }
      />

      {loading ? <LoadingState label="Loading event…" /> : null}

      {error && !loading ? (
        <div className="space-y-4">
          <ErrorState
            message={error}
            onRetry={reload}
            hint="An event outside your visibility scope is indistinguishable from one that does not exist (404) — by design."
          />
          <Link
            to="/audit"
            className="inline-block text-sm font-semibold text-indigo-600 hover:text-indigo-500"
          >
            ← Return to the audit trail
          </Link>
        </div>
      ) : null}

      {data && !loading ? <AuditEventDetailView event={data} /> : null}
    </div>
  )
}
