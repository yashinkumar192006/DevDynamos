import { api } from './client'
import { cleanParams } from './params'
import type { PoliciesQuery, PolicyListResponse } from './types'

/** Active policies for any principal; inactive history for admins only. */
export async function listPolicies(
  query: PoliciesQuery,
): Promise<PolicyListResponse> {
  const { data } = await api.get<PolicyListResponse>('/api/v1/policies', {
    params: cleanParams(query as Record<string, unknown>),
  })
  return data
}
