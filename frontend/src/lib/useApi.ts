/**
 * Minimal data-loading hook used across pages.
 *
 * Loads once per dependency change, exposes `{ data, loading, error }`,
 * and supports an explicit `reload()`. Errors become display strings via
 * the shared `ApiError` normalisation. No caching layers, no fallbacks:
 * if the gateway fails, the page shows the failure (fail-closed UI).
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import { describeError } from './api/errors'

export interface AsyncResource<T> {
  data: T | null
  loading: boolean
  error: string | null
  reload: () => void
}

export function useApiResource<T>(
  loader: () => Promise<T>,
  deps: readonly unknown[],
): AsyncResource<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)

  const loaderRef = useRef(loader)
  loaderRef.current = loader

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    loaderRef
      .current()
      .then((result) => {
        if (!cancelled) setData(result)
      })
      .catch((cause: unknown) => {
        if (!cancelled) setError(describeError(cause))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [...deps, nonce])

  const reload = useCallback(() => setNonce((value) => value + 1), [])
  return { data, loading, error, reload }
}
