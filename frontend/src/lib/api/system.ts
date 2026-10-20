import { api } from './client'
import type { HealthResponse, SystemStatusResponse } from './types'

/** Liveness check (no credentials). */
export async function fetchHealth(): Promise<HealthResponse> {
  const { data } = await api.get<HealthResponse>('/api/v1/health')
  return data
}

/** Provider status — same safe shapes the backend exposes. */
export async function fetchSystemStatus(): Promise<SystemStatusResponse> {
  const { data } = await api.get<SystemStatusResponse>('/api/v1/system/status')
  return data
}
