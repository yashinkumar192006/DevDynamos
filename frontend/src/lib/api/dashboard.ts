import { api } from './client'
import type { DashboardOverview } from './types'

/** Real aggregation over the caller's visible audit trail. */
export async function fetchDashboardOverview(
  windowDays: number,
  recentLimit = 8,
): Promise<DashboardOverview> {
  const { data } = await api.get<DashboardOverview>(
    '/api/v1/dashboard/overview',
    { params: { window_days: windowDays, recent_limit: recentLimit } },
  )
  return data
}
