/**
 * Uniform API error handling for the console.
 *
 * Every failure mode (validation, auth, scope, server, network, timeout)
 * becomes one `ApiError` with a human-readable message, the HTTP status
 * when one exists, and a `network` flag for transport failures. The UI
 * treats transport failures as fail-closed: it shows an error and never
 * falls back to another data source.
 */

import axios from 'axios'

export class ApiError extends Error {
  readonly status?: number
  readonly network: boolean
  readonly timedOut: boolean

  constructor(
    message: string,
    options: { status?: number; network?: boolean; timedOut?: boolean } = {},
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = options.status
    this.network = options.network ?? false
    this.timedOut = options.timedOut ?? false
  }
}

function formatDetail(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value
  if (Array.isArray(value)) {
    // FastAPI 422 shape: [{loc, msg, type}]
    const messages = value
      .map((entry) => {
        if (entry && typeof entry === 'object' && 'msg' in entry) {
          const loc = Array.isArray((entry as { loc?: unknown }).loc)
            ? ((entry as { loc: unknown[] }).loc ?? []).join('.')
            : ''
          return loc
            ? `${loc}: ${String((entry as { msg: unknown }).msg)}`
            : String((entry as { msg: unknown }).msg)
        }
        return String(entry)
      })
      .filter(Boolean)
    if (messages.length) return messages.join('; ')
  }
  return null
}

function extractDetail(data: unknown): string | null {
  if (!data || typeof data !== 'object') return null
  const record = data as { detail?: unknown; error?: unknown }
  // Project contract for HttpExceptions:
  //   {"error": {"type": ..., "detail": ...}}
  if (record.error && typeof record.error === 'object') {
    const wrapped = formatDetail((record.error as { detail?: unknown }).detail)
    if (wrapped) return wrapped
  }
  // Standard FastAPI shapes: {"detail": "..."} / {"detail": [{loc, msg}]}
  return formatDetail(record.detail)
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error
  if (axios.isAxiosError(error)) {
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      return new ApiError('The request to the gateway timed out.', {
        timedOut: true,
      })
    }
    const response = error.response
    if (!response) {
      return new ApiError(
        'Could not reach the ContextShield gateway. Is the backend running? ' +
          '(fail-closed: no data was fetched)',
        { network: true },
      )
    }
    const detail = extractDetail(response.data)
    const fallback: Record<number, string> = {
      400: 'The gateway rejected the request shape.',
      401: 'Your session is invalid or has expired. Please sign in again.',
      403: 'Your account is not permitted to perform this action.',
      404: 'The resource does not exist — or is outside your visibility scope.',
      422: 'The request failed validation.',
      500: 'The gateway reported an internal error (fail-closed).',
      502: 'The gateway is unavailable (bad upstream).',
      503: 'The gateway is unavailable (service not ready).',
    }
    return new ApiError(detail ?? fallback[response.status] ?? `Request failed with status ${response.status}.`, {
      status: response.status,
    })
  }
  return new ApiError('An unexpected error occurred while contacting the gateway.')
}

export function describeError(error: unknown): string {
  return toApiError(error).message
}
