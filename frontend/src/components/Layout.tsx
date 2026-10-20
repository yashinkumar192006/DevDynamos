/**
 * Authenticated app shell: sidebar navigation, mobile slide-over, and a
 * top bar showing the *server-verified* identity and its roles.
 */

import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'
import { RoleChips } from './Badges'

interface NavItem {
  to: string
  label: string
  icon: ReactNode
}

function icon(path: string) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-5 w-5"
      aria-hidden="true"
    >
      <path d={path} />
    </svg>
  )
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: icon('M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z') },
  { to: '/simulator', label: 'Privacy Simulator', icon: icon('M13 2 3 14h7l-1 8 10-12h-7l1-8z') },
  { to: '/audit', label: 'Audit Events', icon: icon('M4 6h16M4 12h16M4 18h16') },
  { to: '/policies', label: 'Policies', icon: icon('M12 3l7 4v5c0 4-3 7-7 9-4-2-7-5-7-9V7l7-4z') },
  { to: '/assets', label: 'Data Assets', icon: icon('M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3') },
  { to: '/system', label: 'System Status', icon: icon('M3 12h4l3-8 4 16 3-8h4') },
  { to: '/sdk', label: 'SDK & Integration', icon: icon('M8 9l-4 3 4 3M16 9l4 3-4 3M13 5l-2 14') },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)

  // Close the mobile sidebar on navigation.
  useEffect(() => {
    setMobileOpen(false)
  }, [location.pathname])

  const roles = user?.roles.map((role) => role.name) ?? []

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-5 py-5">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-600 text-white">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4-3 7-7 9-4-2-7-5-7-9V7l7-4z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12l2 2 3.5-4" />
          </svg>
        </span>
        <div>
          <p className="text-sm font-bold text-white">ContextShield</p>
          <p className="text-xs text-slate-400">Privacy Gateway Console</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-2">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${
                isActive
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`
            }
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-slate-800 px-5 py-4 text-xs text-slate-500">
        Decisions, transformations, and audit entries shown here are produced
        by the real backend — nothing is simulated in the browser.
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-slate-100">
      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 bg-slate-900 lg:block">
        {sidebar}
      </aside>

      {/* Mobile sidebar */}
      {mobileOpen ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-slate-900/60"
            onClick={() => setMobileOpen(false)}
            aria-hidden="true"
          />
          <aside className="absolute inset-y-0 left-0 w-64 bg-slate-900 shadow-xl">
            {sidebar}
          </aside>
        </div>
      ) : null}

      <div className="lg:pl-64">
        <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/90 backdrop-blur">
          <div className="flex items-center justify-between gap-4 px-4 py-3 sm:px-6">
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="rounded-lg p-2 text-slate-600 hover:bg-slate-100 lg:hidden"
                onClick={() => setMobileOpen(true)}
                aria-label="Open navigation"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
                  <path strokeLinecap="round" d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-slate-900">
                  {user?.full_name ?? 'Signed in'}
                </p>
                <div className="mt-0.5 hidden sm:block">
                  <RoleChips roles={roles} />
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => void logout()}
              className="rounded-lg px-3 py-1.5 text-sm font-semibold text-slate-600 ring-1 ring-inset ring-slate-300 hover:bg-slate-50"
            >
              Sign out
            </button>
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
