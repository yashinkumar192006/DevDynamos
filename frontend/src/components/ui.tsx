/**
 * Small shared UI primitives (buttons, cards, form fields, states).
 * Plain Tailwind utilities — no component library, nothing hidden.
 */

import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react'

import type { Pagination as PaginationInfo } from '../lib/api/types'

export function Card({
  children,
  className = '',
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div
      className={`rounded-xl border border-slate-200 bg-white shadow-sm ${className}`}
    >
      {children}
    </div>
  )
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          {title}
        </h1>
        {description ? (
          <div className="mt-1 max-w-3xl text-sm text-slate-600">
            {description}
          </div>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 gap-2">{actions}</div> : null}
    </div>
  )
}

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-indigo-600 text-white hover:bg-indigo-500 focus-visible:outline-indigo-600 disabled:bg-indigo-300',
  secondary:
    'bg-white text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50 disabled:text-slate-400',
  ghost: 'text-slate-600 hover:bg-slate-100 disabled:text-slate-300',
  danger:
    'bg-rose-600 text-white hover:bg-rose-500 disabled:bg-rose-300',
}

export function Button({
  children,
  variant = 'primary',
  className = '',
  type = 'button',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      type={type}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 disabled:cursor-not-allowed ${BUTTON_VARIANTS[variant]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  )
}

export function Field({
  label,
  hint,
  children,
  className = '',
}: {
  label: string
  hint?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <label className={`block ${className}`}>
      <span className="mb-1 block text-sm font-medium text-slate-700">
        {label}
      </span>
      {children}
      {hint ? <span className="mt-1 block text-xs text-slate-500">{hint}</span> : null}
    </label>
  )
}

const INPUT_CLASSES =
  'block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 disabled:bg-slate-50 disabled:text-slate-500'

export function TextInput({
  className = '',
  ...rest
}: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`${INPUT_CLASSES} ${className}`} {...rest} />
}

export function TextArea({
  className = '',
  ...rest
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={`${INPUT_CLASSES} ${className}`} {...rest} />
}

export function Select({
  className = '',
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={`${INPUT_CLASSES} ${className}`} {...rest}>
      {children}
    </select>
  )
}

export function Spinner({ className = '' }: { className?: string }) {
  return (
    <svg
      className={`h-5 w-5 animate-spin text-slate-400 ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 0 1 8-8v4a4 4 0 0 0-4 4H4z"
      />
    </svg>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 rounded-xl border border-dashed border-slate-300 bg-white/60 px-6 py-12 text-sm text-slate-500">
      <Spinner />
      {label}
    </div>
  )
}

export function ErrorState({
  message,
  onRetry,
  hint,
}: {
  message: string
  onRetry?: () => void
  hint?: string
}) {
  return (
    <div className="rounded-xl border border-rose-200 bg-rose-50 px-5 py-6">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 text-rose-500" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="currentColor" className="h-5 w-5">
            <path
              fillRule="evenodd"
              d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm-.75-11.5a.75.75 0 0 1 1.5 0v5a.75.75 0 0 1-1.5 0v-5Zm.75 8.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"
              clipRule="evenodd"
            />
          </svg>
        </span>
        <div className="flex-1">
          <p className="text-sm font-semibold text-rose-800">
            Something went wrong
          </p>
          <p className="mt-1 text-sm text-rose-700">{message}</p>
          {hint ? <p className="mt-1 text-xs text-rose-600">{hint}</p> : null}
        </div>
        {onRetry ? (
          <Button variant="secondary" onClick={onRetry}>
            Retry
          </Button>
        ) : null}
      </div>
    </div>
  )
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description?: ReactNode
  action?: ReactNode
}) {
  return (
    <div className="rounded-xl border border-dashed border-slate-300 bg-white/60 px-6 py-12 text-center">
      <p className="text-sm font-semibold text-slate-700">{title}</p>
      {description ? (
        <div className="mx-auto mt-1 max-w-md text-sm text-slate-500">
          {description}
        </div>
      ) : null}
      {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
    </div>
  )
}

export function Callout({
  tone = 'info',
  title,
  children,
}: {
  tone?: 'info' | 'warning' | 'danger' | 'success'
  title?: string
  children: ReactNode
}) {
  const tones = {
    info: 'border-sky-200 bg-sky-50 text-sky-800',
    warning: 'border-amber-200 bg-amber-50 text-amber-800',
    danger: 'border-rose-200 bg-rose-50 text-rose-800',
    success: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  }
  return (
    <div className={`rounded-xl border px-4 py-3 text-sm ${tones[tone]}`}>
      {title ? <p className="font-semibold">{title}</p> : null}
      <div className={title ? 'mt-1' : ''}>{children}</div>
    </div>
  )
}

export function StatCard({
  label,
  value,
  hint,
  tone = 'default',
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
  tone?: 'default' | 'success' | 'warning' | 'danger' | 'info'
}) {
  const tones = {
    default: 'text-slate-900',
    success: 'text-emerald-600',
    warning: 'text-amber-600',
    danger: 'text-rose-600',
    info: 'text-sky-600',
  }
  return (
    <Card className="px-5 py-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <p className={`mt-2 text-3xl font-bold tabular-nums ${tones[tone]}`}>
        {value}
      </p>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </Card>
  )
}

export function KeyValue({
  label,
  children,
  mono = false,
}: {
  label: string
  children: ReactNode
  mono?: boolean
}) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        {label}
      </dt>
      <dd
        className={`mt-0.5 break-words text-sm text-slate-800 ${mono ? 'font-mono text-xs' : ''}`}
      >
        {children}
      </dd>
    </div>
  )
}

export function Chips({ values, empty = '—' }: { values: string[]; empty?: string }) {
  if (!values.length) return <span className="text-sm text-slate-400">{empty}</span>
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((value, index) => (
        <span
          key={`${value}-${index}`}
          className="inline-flex rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-700"
        >
          {value}
        </span>
      ))}
    </span>
  )
}

export function Pagination({
  pagination,
  onOffsetChange,
}: {
  pagination: PaginationInfo
  onOffsetChange: (offset: number) => void
}) {
  const from = pagination.total === 0 ? 0 : pagination.offset + 1
  const to = pagination.offset + Math.min(
    pagination.limit,
    Math.max(pagination.total - pagination.offset, 0),
  )
  return (
    <div className="flex items-center justify-between gap-4 border-t border-slate-200 px-4 py-3 text-sm text-slate-600">
      <span>
        Showing <span className="font-semibold">{from}</span>–
        <span className="font-semibold">{to}</span> of{' '}
        <span className="font-semibold">{pagination.total}</span>
      </span>
      <div className="flex gap-2">
        <Button
          variant="secondary"
          disabled={pagination.offset === 0}
          onClick={() =>
            onOffsetChange(Math.max(0, pagination.offset - pagination.limit))
          }
        >
          Previous
        </Button>
        <Button
          variant="secondary"
          disabled={!pagination.has_more}
          onClick={() => onOffsetChange(pagination.offset + pagination.limit)}
        >
          Next
        </Button>
      </div>
    </div>
  )
}
