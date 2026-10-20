/**
 * Authentication state for the console.
 *
 * The token is a bearer token issued by the real login endpoint and is
 * attached to every request by the shared Axios client. Identity comes
 * from `GET /api/v1/auth/me` — never from client-side claims. On a 401
 * the session is cleared and the router redirects to /login with a
 * "session expired" notice.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import type { ReactNode } from 'react'

import {
  getStoredToken,
  setStoredToken,
  setUnauthorizedHandler,
} from '../lib/api/client'
import { fetchMe, login as apiLogin, logout as apiLogout } from '../lib/api/auth'
import type { UserProfile } from '../lib/api/types'

type AuthStatus = 'loading' | 'authenticated' | 'anonymous'

export interface AuthContextValue {
  user: UserProfile | null
  status: AuthStatus
  sessionExpired: boolean
  login: (username: string, password: string) => Promise<UserProfile>
  logout: () => Promise<void>
  acknowledgeSessionExpired: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null)
  const [status, setStatus] = useState<AuthStatus>('loading')
  const [sessionExpired, setSessionExpired] = useState(false)

  // A 401 anywhere clears the session and flags the expiry notice.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setStoredToken(null)
      setUser(null)
      setStatus('anonymous')
      setSessionExpired(true)
    })
    return () => setUnauthorizedHandler(null)
  }, [])

  // Resume a stored session by asking the backend who we are.
  useEffect(() => {
    let cancelled = false
    async function bootstrap() {
      if (!getStoredToken()) {
        setStatus('anonymous')
        return
      }
      try {
        const profile = await fetchMe()
        if (!cancelled) {
          setUser(profile)
          setStatus('authenticated')
        }
      } catch {
        if (!cancelled) {
          setStoredToken(null)
          setStatus('anonymous')
        }
      }
    }
    void bootstrap()
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(
    async (username: string, password: string): Promise<UserProfile> => {
      const response = await apiLogin(username, password)
      setStoredToken(response.access_token)
      setUser(response.user)
      setStatus('authenticated')
      setSessionExpired(false)
      return response.user
    },
    [],
  )

  const logout = useCallback(async () => {
    try {
      await apiLogout()
    } catch {
      // The client discards the token regardless; the backend can still
      // have recorded the logout event.
    }
    setStoredToken(null)
    setUser(null)
    setStatus('anonymous')
    setSessionExpired(false)
  }, [])

  const acknowledgeSessionExpired = useCallback(() => {
    setSessionExpired(false)
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      status,
      sessionExpired,
      login,
      logout,
      acknowledgeSessionExpired,
    }),
    [user, status, sessionExpired, login, logout, acknowledgeSessionExpired],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used inside <AuthProvider>')
  }
  return context
}
