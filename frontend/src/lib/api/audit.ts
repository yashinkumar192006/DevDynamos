import { api } from './client'
import { cleanParams } from './params'
import type {
  AuditEventDetail,
  AuditEventsQuery,
  AuditEventsResponse,
} from './types'

/** Visibility-scoped, filtered, paginated audit query. */
export async function listAuditEvents(
  query: AuditEventsQuery,
): Promise<AuditEventsResponse> {
  const { data } = await api.get<AuditEventsResponse>('/api/v1/audit/events', {
    params: cleanParams(query as Record<string, unknown>),
  })
  return data
}

/** Full explainability for one event (404 when out of scope). */
export async function getAuditEvent(eventId: string): Promise<AuditEventDetail> {
  const { data } = await api.get<AuditEventDetail>(
    `/api/v1/audit/events/${encodeURIComponent(eventId)}`,
  )
  return data
}
