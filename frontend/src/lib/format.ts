/** Display formatting helpers. Pure functions — no fabricated data. */

export function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatDate(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  })
}

export function shortId(value?: string | null, length = 12): string {
  if (!value) return '—'
  return value.length > length ? `${value.slice(0, length)}…` : value
}

export function prettyValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export function scopeLabel(scope?: string | null): string {
  switch (scope) {
    case 'full':
      return 'Full trail (administrator)'
    case 'privacy_trail':
      return 'Privacy trail (compliance role)'
    case 'own':
      return 'Own events only'
    default:
      return scope ?? 'unknown'
  }
}

export function humanizeAction(action?: string | null): string {
  if (!action) return '—'
  return action.replace(/_/g, ' ')
}
