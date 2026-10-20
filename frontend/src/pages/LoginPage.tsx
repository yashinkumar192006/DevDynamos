/**
 * Login page.
 *
 * Credentials go to `POST /api/v1/auth/login` — the backend validates them
 * and assigns roles. The demo-account buttons only prefill the form; they
 * cannot grant a role or bypass the authorization engine in any way.
 */

import { useState } from 'react'
import type { FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'
import { DEMO_ACCOUNTS } from '../lib/demoAccounts'
import { describeError } from '../lib/api/errors'
import { Button, Field, TextInput } from '../components/ui'

interface LocationState {
  from?: string
}

export default function LoginPage() {
  const { status, sessionExpired, login, acknowledgeSessionExpired } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const state = (location.state ?? {}) as LocationState

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  if (status === 'authenticated') {
    return <Navigate to={state.from ?? '/dashboard'} replace />
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (submitting) return
    setSubmitting(true)
    setError(null)
    acknowledgeSessionExpired()
    try {
      await login(username.trim(), password)
      navigate(state.from ?? '/dashboard', { replace: true })
    } catch (cause) {
      setError(describeError(cause))
    } finally {
      setSubmitting(false)
    }
  }

  function fillDemo(demoUsername: string, demoPassword: string) {
    setUsername(demoUsername)
    setPassword(demoPassword)
    setError(null)
  }

  return (
    <div className="flex min-h-screen bg-slate-100">
      {/* Brand panel */}
      <div className="relative hidden w-1/2 flex-col justify-between bg-slate-900 px-12 py-12 lg:flex">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-600 text-white">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-6 w-6" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4-3 7-7 9-4-2-7-5-7-9V7l7-4z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12l2 2 3.5-4" />
            </svg>
          </span>
          <div>
            <p className="text-lg font-bold text-white">ContextShield</p>
            <p className="text-xs text-slate-400">Privacy Gateway Console</p>
          </div>
        </div>
        <div>
          <h1 className="max-w-md text-3xl font-bold leading-tight text-white">
            Watch a real privacy gateway make real decisions.
          </h1>
          <ul className="mt-8 space-y-4 text-sm text-slate-300">
            <li className="flex gap-3">
              <span className="mt-0.5 text-indigo-400">◆</span>
              Every request is evaluated server-side against versioned
              policies — the browser never decides anything.
            </li>
            <li className="flex gap-3">
              <span className="mt-0.5 text-indigo-400">◆</span>
              Blocked fields stay blocked: the gateway returns reason codes,
              not data.
            </li>
            <li className="flex gap-3">
              <span className="mt-0.5 text-indigo-400">◆</span>
              Each decision lands in a tamper-evident audit trail you can
              inspect, filter, and explain.
            </li>
          </ul>
        </div>
        <p className="text-xs text-slate-500">
          Demo environment with synthetic data. Never enter real personal data.
        </p>
      </div>

      {/* Form panel */}
      <div className="flex w-full items-center justify-center px-4 py-12 lg:w-1/2">
        <div className="w-full max-w-md">
          <div className="mb-8 lg:hidden">
            <p className="text-lg font-bold text-slate-900">ContextShield</p>
            <p className="text-xs text-slate-500">Privacy Gateway Console</p>
          </div>

          {sessionExpired ? (
            <div className="mb-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
              Your session expired or was revoked. Please sign in again — no
              data was retained from the previous session.
            </div>
          ) : null}

          <h2 className="text-2xl font-bold text-slate-900">Sign in</h2>
          <p className="mt-1 text-sm text-slate-600">
            Use a seeded demo account or your own credentials. Authentication
            and roles are handled by the backend.
          </p>

          <form onSubmit={(event) => void handleSubmit(event)} className="mt-6 space-y-4">
            <Field label="Username">
              <TextInput
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                required
                placeholder="e.g. sarah.chen"
              />
            </Field>
            <Field label="Password">
              <TextInput
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
                placeholder="••••••••"
              />
            </Field>

            {error ? (
              <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700">
                {error}
              </div>
            ) : null}

            <Button type="submit" disabled={submitting} className="w-full">
              {submitting ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>

          <div className="mt-8">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Demo identities
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Prefills the form with a seeded account. The role shown comes
              from the signed-in backend session.
            </p>
            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {DEMO_ACCOUNTS.map((account) => (
                <button
                  key={account.username}
                  type="button"
                  onClick={() => fillDemo(account.username, account.password)}
                  className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-left transition hover:border-indigo-300 hover:bg-indigo-50/50"
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-800">
                      {account.displayName}
                    </span>
                    <span className="rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
                      {account.role}
                    </span>
                  </span>
                  <span className="mt-0.5 block text-xs text-slate-500">
                    {account.blurb}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
