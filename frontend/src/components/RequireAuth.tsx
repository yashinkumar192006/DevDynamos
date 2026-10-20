/**
 * Route guard: renders children only for authenticated sessions.
 *
 * While the stored token is being verified, a full-page loader is shown.
 * Anonymous users are redirected to /login, remembering where they were
 * heading so the login page can send them back afterwards. The guard is
 * a UX affordance only — every API call is authorised server-side.
 */

import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'
import { Spinner } from './ui'

export default function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  const location = useLocation()

  if (status === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center gap-3 bg-slate-100 text-sm text-slate-500">
        <Spinner />
        Verifying session…
      </div>
    )
  }

  if (status !== 'authenticated') {
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: `${location.pathname}${location.search}` }}
      />
    )
  }

  return <>{children}</>
}
