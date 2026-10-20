/**
 * Shared Axios client for the ContextShield gateway.
 *
 * Base URL comes from `VITE_API_BASE_URL` (default http://localhost:8000).
 * The client attaches the bearer token when one is stored and normalises
 * every failure into `ApiError`. A 401 from a non-login request triggers
 * the registered "session expired" handler — the auth provider clears
 * the session and the router sends the user back to the login page.
 *
 * No credentials are ever stored in the bundle: only the token returned
 * by the real login endpoint, kept in localStorage for the demo console.
 */

import axios, { AxiosError } from 'axios'

import { toApiError } from './errors'

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/+$/, '') ||
  'http://localhost:8000'

const TOKEN_STORAGE_KEY = 'contextshield.token'

export function getStoredToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY)
  } catch {
    return null
  }
}

export function setStoredToken(token: string | null): void {
  try {
    if (token) window.localStorage.setItem(TOKEN_STORAGE_KEY, token)
    else window.localStorage.removeItem(TOKEN_STORAGE_KEY)
  } catch {
    // Storage unavailable (private mode) — the in-memory state still works.
  }
}

type UnauthorizedHandler = () => void
let unauthorizedHandler: UnauthorizedHandler | null = null

/** Registered by the auth provider to clear the session on a 401. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler
}

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15_000,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = getStoredToken()
  if (token) {
    config.headers.set('Authorization', `Bearer ${token}`)
  }
  return config
})

function isLoginAttempt(error: AxiosError): boolean {
  const url = error.config?.url ?? ''
  return url.includes('/auth/login')
}

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    const apiError = toApiError(error)
    if (apiError.status === 401 && !isLoginAttempt(error)) {
      unauthorizedHandler?.()
    }
    return Promise.reject(apiError)
  },
)
