/** 404 page for unknown routes. */

import { Link } from 'react-router-dom'

import { Button } from '../components/ui'

export default function NotFoundPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white px-8 py-10 text-center shadow-sm">
        <p className="text-5xl font-black text-slate-200">404</p>
        <h1 className="mt-3 text-xl font-bold text-slate-900">
          Page not found
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          That route does not exist in the console. Check the address, or use
          the links below.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link to="/dashboard">
            <Button>Back to dashboard</Button>
          </Link>
          <Link to="/simulator">
            <Button variant="secondary">Privacy Simulator</Button>
          </Link>
        </div>
      </div>
    </div>
  )
}
