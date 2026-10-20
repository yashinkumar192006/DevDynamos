/**
 * Application routes.
 *
 * Pages are loaded lazily so the dashboard chart library only ships when
 * needed. Production note: this is a client-side-routed SPA, so the web
 * server must serve index.html for unknown paths (deep-link handling).
 * The Vite dev server does this out of the box; `vite preview` does as
 * well. For other hosts, add an SPA fallback rewrite to index.html.
 */

import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import { AuthProvider } from './auth/AuthContext'
import Layout from './components/Layout'
import RequireAuth from './components/RequireAuth'
import { Spinner } from './components/ui'
import LoginPage from './pages/LoginPage'
import NotFoundPage from './pages/NotFoundPage'
import UnauthorizedPage from './pages/UnauthorizedPage'

const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const SimulatorPage = lazy(() => import('./pages/SimulatorPage'))
const AuditEventsPage = lazy(() => import('./pages/AuditEventsPage'))
const AuditEventDetailPage = lazy(() => import('./pages/AuditEventDetailPage'))
const PoliciesPage = lazy(() => import('./pages/PoliciesPage'))
const AssetsPage = lazy(() => import('./pages/AssetsPage'))
const SystemStatusPage = lazy(() => import('./pages/SystemStatusPage'))
const SdkPage = lazy(() => import('./pages/SdkPage'))

function PageFallback() {
  return (
    <div className="flex items-center justify-center gap-3 py-24 text-sm text-slate-500">
      <Spinner />
      Loading…
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/unauthorized" element={<UnauthorizedPage />} />

        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route
            path="/dashboard"
            element={
              <Suspense fallback={<PageFallback />}>
                <DashboardPage />
              </Suspense>
            }
          />
          <Route
            path="/simulator"
            element={
              <Suspense fallback={<PageFallback />}>
                <SimulatorPage />
              </Suspense>
            }
          />
          <Route
            path="/audit"
            element={
              <Suspense fallback={<PageFallback />}>
                <AuditEventsPage />
              </Suspense>
            }
          />
          <Route
            path="/audit/:id"
            element={
              <Suspense fallback={<PageFallback />}>
                <AuditEventDetailPage />
              </Suspense>
            }
          />
          <Route
            path="/policies"
            element={
              <Suspense fallback={<PageFallback />}>
                <PoliciesPage />
              </Suspense>
            }
          />
          <Route
            path="/assets"
            element={
              <Suspense fallback={<PageFallback />}>
                <AssetsPage />
              </Suspense>
            }
          />
          <Route
            path="/system"
            element={
              <Suspense fallback={<PageFallback />}>
                <SystemStatusPage />
              </Suspense>
            }
          />
          <Route
            path="/sdk"
            element={
              <Suspense fallback={<PageFallback />}>
                <SdkPage />
              </Suspense>
            }
          />
        </Route>

        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AuthProvider>
  )
}
