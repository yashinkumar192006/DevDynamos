/**
 * TypeScript mirrors of the ContextShield gateway contracts.
 *
 * These types describe what the *backend* returns; the frontend never
 * invents data. Every response is typed from the backend schemas
 * (auth, privacy, audit, policies, assets, dashboard, system).
 */

// ── Auth ────────────────────────────────────────────────────────────

export interface PermissionInfo {
  resource: string
  action: string
}

export interface RoleInfo {
  name: string
  description?: string | null
}

export interface UserProfile {
  id: string
  username: string
  email: string
  full_name: string
  department?: string | null
  employee_id?: string | null
  is_active: boolean
  roles: RoleInfo[]
  permissions: PermissionInfo[]
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: UserProfile
}

// ── Secure request ─────────────────────────────────────────────────

export type OverallDecision =
  | 'ALLOW'
  | 'PARTIAL_ALLOW'
  | 'BLOCK'
  | 'ESCALATION_NEEDED'

export interface FieldDecision {
  action: string
  value: unknown
  reason_code?: string | null
  reason?: string | null
  policy_id?: string | null
  policy_version?: number | null
}

export interface GuardFinding {
  category?: string | null
  rule?: string | null
  permitted: boolean
  start?: number | null
  end?: number | null
  redacted_as?: string | null
}

export interface LLMGuard {
  triggered: boolean
  action: string
  reason_code?: string | null
  findings: GuardFinding[]
}

export interface LLMInfo {
  requested: boolean
  invoked: boolean
  provider?: string | null
  model?: string | null
  error_code?: string | null
  error?: string | null
  guard?: LLMGuard | null
}

export interface SecureRequestPayload {
  resource: string
  data_fields: string[]
  purpose: string
  operation?: 'read' | 'aggregate'
  target_entity?: string | null
  purpose_detail?: string | null
  context?: { session_id?: string; agent_name?: string } | null
  include_llm_response?: boolean
}

export interface SecureRequestResult {
  request_id: string
  overall_decision: OverallDecision
  reason_code?: string | null
  reason?: string | null
  fields: Record<string, FieldDecision>
  records?: Record<string, unknown>[] | null
  retrieved: boolean
  llm_response?: string | null
  llm?: LLMInfo | null
  guard_triggered: boolean
  mosaic_warning: boolean
  audit_id?: string | null
  timestamp: string
}

// ── Audit ───────────────────────────────────────────────────────────

export interface AuditActorInfo {
  id?: string | null
  kind: string
  name?: string | null
  roles: string[]
  scopes: string[]
}

export interface AuditDecisionEntry {
  field: string
  action: string
  reason_code: string
  policy_id?: string | null
  policy_version?: number | null
  sensitivity?: string | null
  pii_category?: string | null
}

export interface AuditTransformationEntry {
  field: string
  transformation: string
}

export interface AuditLLMInfo {
  requested: boolean
  invoked: boolean
  provider?: string | null
  model?: string | null
  guard_triggered: boolean
  guard_action?: string | null
  guard_reason_code?: string | null
  error_code?: string | null
}

export interface AuditEventSummary {
  id: string
  timestamp: string
  action: string
  outcome?: string | null
  actor: AuditActorInfo
  request_id?: string | null
  session_id?: string | null
  resource?: string | null
  resource_id?: string | null
  overall_decision?: string | null
  reason_codes: string[]
  policy_versions: number[]
  sensitivity_categories: string[]
  model_requested: boolean
  model_invoked: boolean
  guard_outcome?: string | null
  mosaic_warning: boolean
}

export interface AuditEventDetail extends AuditEventSummary {
  purpose?: string | null
  purpose_recognized?: boolean | null
  operation?: string | null
  subject_scope?: string | null
  flags: string[]
  requested_fields: string[]
  decisions: AuditDecisionEntry[]
  transformations: AuditTransformationEntry[]
  llm?: AuditLLMInfo | null
  guard_triggered: boolean
  correlation: Record<string, unknown>
  ip_address?: string | null
  requester?: Record<string, unknown> | null
  agent?: Record<string, unknown> | null
}

export interface Pagination {
  total: number
  limit: number
  offset: number
  has_more: boolean
}

export interface AuditEventsResponse {
  items: AuditEventSummary[]
  pagination: Pagination
}

export interface AuditEventsQuery {
  limit?: number
  offset?: number
  action?: string
  requester_id?: string
  resource?: string
  outcome?: string
  session_id?: string
  start_date?: string
  end_date?: string
}

// ── Policies ────────────────────────────────────────────────────────

export interface PolicyItem {
  id: string
  name: string
  version: number
  description?: string | null
  policy_text: string
  resource_pattern: string
  required_role?: string | null
  min_sensitivity?: string | null
  allowed_purposes: string[]
  allowed_actions: string[]
  action?: string | null
  priority: number
  status: string
  is_active: boolean
  effective_from: string
  effective_until?: string | null
}

export interface PolicyListResponse {
  items: PolicyItem[]
  pagination: Pagination
}

export interface PoliciesQuery {
  limit?: number
  offset?: number
  resource?: string
  role?: string
  include_inactive?: boolean
}

// ── Data assets ─────────────────────────────────────────────────────

export interface AssetField {
  name: string
  column_name?: string | null
  field_type: string
  sensitivity: string
  pii_category?: string | null
  description?: string | null
}

export interface DataAssetItem {
  id: string
  name: string
  description?: string | null
  asset_type: string
  owner_department?: string | null
  table_name?: string | null
  field_count: number
  sensitivity_summary: Record<string, number>
  record_count?: number | null
  fields: AssetField[]
}

export interface DataAssetListResponse {
  items: DataAssetItem[]
  pagination: Pagination
}

export interface AssetsQuery {
  limit?: number
  offset?: number
  sensitivity?: string
  asset_type?: string
}

// ── Dashboard ───────────────────────────────────────────────────────

export interface DashboardSummary {
  window_days: number
  total_requests: number
  decisions: Record<string, number>
  requests_with_transformations: number
  model_invocations: number
  guard_triggered: number
  mosaic_warnings: number
}

export interface DashboardDailyPoint {
  date: string
  total: number
  allow: number
  partial_allow: number
  block: number
  escalation: number
}

export interface DashboardLLMHealth {
  provider?: string
  model?: string
  configured?: boolean
  status?: string
  detail?: string | null
  guard?: Record<string, unknown>
}

export interface DashboardHealth {
  database: string
  database_latency_ms?: number | null
  llm: DashboardLLMHealth
  classifier: Record<string, unknown>
}

export interface DashboardOverview {
  scope: 'full' | 'privacy_trail' | 'own' | string
  window_days: number
  summary: DashboardSummary
  daily: DashboardDailyPoint[]
  recent_decisions: AuditEventSummary[]
  policy_stats: {
    active_policies: number
    most_triggered_policy?: string | null
  }
  health: DashboardHealth
  timestamp: string
}

// ── System ──────────────────────────────────────────────────────────

export interface SystemStatusResponse {
  providers: {
    database: string
    llm: DashboardLLMHealth
    classifier: Record<string, unknown>
  }
}

export interface HealthResponse {
  status: string
}
