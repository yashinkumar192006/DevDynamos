/**
 * Status badges. Colours communicate the *backend's* decision, action,
 * outcome, sensitivity, or status values — the frontend adds no meaning
 * of its own.
 */

const BASE =
  'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ring-1 ring-inset whitespace-nowrap'

function pick(candidate: string | null | undefined, map: Record<string, string>): string {
  const key = (candidate ?? '').toUpperCase()
  return map[key] ?? 'bg-slate-100 text-slate-600 ring-slate-200'
}

export function decisionClasses(decision?: string | null): string {
  return pick(decision, {
    ALLOW: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    PARTIAL_ALLOW: 'bg-amber-50 text-amber-700 ring-amber-200',
    BLOCK: 'bg-rose-50 text-rose-700 ring-rose-200',
    ESCALATION_NEEDED: 'bg-sky-50 text-sky-700 ring-sky-200',
  })
}

export function actionClasses(action?: string | null): string {
  return pick(action, {
    ALLOW: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    MASK: 'bg-amber-50 text-amber-700 ring-amber-200',
    TOKENIZE: 'bg-violet-50 text-violet-700 ring-violet-200',
    GENERALIZE: 'bg-indigo-50 text-indigo-700 ring-indigo-200',
    AGGREGATE: 'bg-cyan-50 text-cyan-700 ring-cyan-200',
    BLOCK: 'bg-rose-50 text-rose-700 ring-rose-200',
    ESCALATE: 'bg-sky-50 text-sky-700 ring-sky-200',
  })
}

export function outcomeClasses(outcome?: string | null): string {
  return pick(outcome, {
    SUCCESS: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    PASSED: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    FLAGGED: 'bg-amber-50 text-amber-700 ring-amber-200',
    ESCALATED: 'bg-sky-50 text-sky-700 ring-sky-200',
    DENIED: 'bg-rose-50 text-rose-700 ring-rose-200',
    FAILED: 'bg-rose-50 text-rose-700 ring-rose-200',
  })
}

export function sensitivityClasses(level?: string | null): string {
  return pick(level, {
    LOW: 'bg-slate-100 text-slate-600 ring-slate-200',
    MEDIUM: 'bg-sky-50 text-sky-700 ring-sky-200',
    HIGH: 'bg-amber-50 text-amber-700 ring-amber-200',
    RESTRICTED: 'bg-rose-50 text-rose-700 ring-rose-200',
  })
}

export function statusClasses(status?: string | null): string {
  return pick(status, {
    ACTIVE: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    DRAFT: 'bg-amber-50 text-amber-700 ring-amber-200',
    SUPERSEDED: 'bg-slate-100 text-slate-600 ring-slate-200',
    ARCHIVED: 'bg-slate-100 text-slate-600 ring-slate-200',
    HEALTHY: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    READY: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
    OK: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  })
}

export function Badge({
  value,
  classes,
  fallback = '—',
}: {
  value?: string | null
  classes?: string
  fallback?: string
}) {
  return (
    <span className={`${BASE} ${classes ?? 'bg-slate-100 text-slate-600 ring-slate-200'}`}>
      {value ?? fallback}
    </span>
  )
}

export function DecisionBadge({ decision }: { decision?: string | null }) {
  return <Badge value={decision} classes={decisionClasses(decision)} />
}

export function ActionBadge({ action }: { action?: string | null }) {
  return <Badge value={action} classes={actionClasses(action)} />
}

export function OutcomeBadge({ outcome }: { outcome?: string | null }) {
  return <Badge value={outcome} classes={outcomeClasses(outcome)} />
}

export function SensitivityBadge({ level }: { level?: string | null }) {
  return <Badge value={level} classes={sensitivityClasses(level)} />
}

export function StatusBadge({ status }: { status?: string | null }) {
  return <Badge value={status} classes={statusClasses(status)} />
}

export function RoleChips({ roles }: { roles: string[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {roles.map((role) => (
        <span
          key={role}
          className="inline-flex rounded-md bg-indigo-50 px-1.5 py-0.5 text-xs font-medium text-indigo-700 ring-1 ring-inset ring-indigo-100"
        >
          {role}
        </span>
      ))}
    </span>
  )
}
