import { api } from './client'
import { cleanParams } from './params'
import type { AssetsQuery, DataAssetListResponse } from './types'

/** Classification metadata for catalog assets (never row data). */
export async function listAssets(
  query: AssetsQuery,
): Promise<DataAssetListResponse> {
  const { data } = await api.get<DataAssetListResponse>('/api/v1/data/assets', {
    params: cleanParams(query as Record<string, unknown>),
  })
  return data
}
