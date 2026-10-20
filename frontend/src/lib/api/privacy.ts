import { api } from './client'
import type { SecureRequestPayload, SecureRequestResult } from './types'

/**
 * Send a real governed request through the gateway.
 *
 * The response is exactly what the backend authorised: per-field
 * decisions with already-transformed values, and nothing else.
 */
export async function secureRequest(
  payload: SecureRequestPayload,
): Promise<SecureRequestResult> {
  const { data } = await api.post<SecureRequestResult>(
    '/api/v1/privacy/secure-request',
    payload,
  )
  return data
}
