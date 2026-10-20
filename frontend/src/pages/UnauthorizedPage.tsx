/**
 * 403 page — shown when an action was denied by the backend.
 *
 * The console does not "work around" denials: this page explains the
 * server-side enforcement and offers safe navigation only.
 */

import { Link } from 'react-router-dom'

import { Button } from '../components/ui'

export default function UnauthorizedPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white px-8 py-10 text-center shadow-sm">
        <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-rose-50 text-rose-600">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-7 w-7" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4-3 7-7 9-4-2-7-5-7-9V7l7-4z" />
            <path strokeLinecap="round" d="M9 12h6" />
          </svg>
        </span>
        <h1 className="mt-4 text-xl font-bold text-slate-900">
          Not authorized
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Your account is not permitted to perform that action. Authorization
          is enforced by the ContextShield backend — the console cannot and
          will not bypass it.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link to="/dashboard">
            <Button>Back to dashboard</Button>
          </Link>
          <Link to="/audit">
            <Button variant="secondary">Your audit trail</Button>
          </Link>
        </div>
        <p className="mt-6 text-xs text-slate-400">
          If you believe this is wrong, ask an administrator to check your
          role assignments.
        </p>
      </div>
    </div>
  )
}
