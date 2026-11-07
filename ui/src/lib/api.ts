/** Typed transport for the existing FastAPI read API. Never accepts absolute URLs. */
export type ItemKind = 'job_posting' | 'news' | 'advisory' | 'vulnerability' | 'company_update'
export type ItemState = 'current' | 'unknown' | 'stale' | 'closed'

export interface Item {
  id: number
  source: string
  kind: ItemKind
  title: string
  organization: string | null
  url: string
  state: ItemState
  first_seen_at: string
  last_seen_at: string
  published_at: string | null
  updated_at: string | null
  current_version: number
}
export interface ItemDetail extends Item {
  attributes: Record<string, unknown>
  provenance: Record<string, unknown>
}
export interface ItemVersion {
  version: number
  observed_at: string
  sha256: string
  attributes: Record<string, unknown>
  provenance: Record<string, unknown>
}
export interface ItemPage {
  items: Item[]
  next_cursor: number | null
}
export interface Source {
  id: string
  kind: 'rss' | 'json_api' | 'html'
  item_kind: ItemKind
  enabled: boolean
  last_success_at: string | null
  next_due_at: string
  last_error: string | null
}
export interface CveReference {
  item_id: number
  source: string
  relation: 'kev' | 'record' | 'reference' | 'title_mention'
  kind: ItemKind
  state: ItemState
  title: string
  url: string
  last_seen_at: string
  source_url: string
  source_adapter: string
}
export interface KevStatus {
  status: 'listed' | 'not_listed' | 'unknown'
  catalog_as_of: string | null
  catalog_fresh: boolean
  item_id: number | null
  date_added: string | null
  due_date: string | null
  vendor: string | null
  product: string | null
  known_ransomware_campaign_use: string | null
  source_url: string | null
}
export interface EpssObservation {
  status: 'unknown' | 'not_scored' | 'stale' | 'current'
  score: number | null
  percentile: number | null
  score_date: string | null
  observed_at: string | null
  source_url: string
}
export interface CveDetail {
  epss: EpssObservation
  cve_id: string
  canonical_url: string
  kev: KevStatus
  references: CveReference[]
  references_truncated: boolean
}
export interface SourceDefinition {
  id: string
  kind: 'rss' | 'json_api' | 'html'
  url: string
  adapter: string
  item_kind: ItemKind
  organization?: string | null
  interval_minutes: number
  max_requests_per_hour: number
  max_concurrency: number
  max_pages?: number
  enabled: boolean
  policy: { reviewed_at: string; terms_url?: string | null; robots_url?: string | null; content_storage: 'metadata_only'; note: string; license_id?: string; license_url?: string | null; attribution?: string | null }
  json_path?: string | null
  field_map?: Record<string, string>
  selectors?: Record<string, string>
}
export interface ManagedSource {
  id: string
  origin: 'official' | 'custom'
  config: SourceDefinition
  overrides: Record<string, number | boolean>
  catalog_revision: string | null
  enabled: boolean
  last_success_at: string | null
  next_due_at: string
  last_error: string | null
}
export interface CatalogEntry {
  config: SourceDefinition
  catalog_revision: string
  installed: boolean
  runtime: ManagedSource | null
}
export interface ProbeResult {
  source: string
  entries: number
  status: number
  sample: { title: string; url: string }[]
}
export interface Change {
  item_id: number
  kind: ItemKind
  title: string
  version: number
  observed_at: string
}
export interface ChangesPage { changes: Change[] }

export type ReportTemplateId = 'security-daily' | 'cve-kev-deep-dive'
export type ReportRunState = 'queued' | 'leased' | 'running' | 'validating' | 'publishing'
  | 'published' | 'skipped' | 'failed' | 'cancelled'

export interface ReportTemplate {
  id: ReportTemplateId
  revision: number
  revision_key: string
  title: string
  category: 'security' | 'cve'
  parameters_schema: Record<string, unknown>
  evidence_limits: Record<string, number>
  outline: string[]
}

export interface ReportRunListItem {
  run_id: string
  template_id: ReportTemplateId
  created_at: string
  trigger: 'manual' | 'scheduled'
  state: ReportRunState
  stage: string
  attempts: number
  error_code: string | null
  failed_stage: string | null
  retry_at: string | null
  published_url: string | null
}

export interface ReportRunEvent {
  attempt: number
  seq: number
  created_at: string
  stage: string
  event_type: string
  error_code: string | null
  exit_status: number | null
  elapsed_ms: number | null
  usage: Record<string, number> | null
  artifact_sha256: string | null
  diagnostic_ref: string | null
  retryable: boolean | null
  cli_version: string | null
  stdout_bytes: number | null
  stderr_bytes: number | null
  jsonl_last_event: string | null
}

export interface ReportRun extends ReportRunListItem {
  parameters: Record<string, unknown>
  stages: Record<string, string>
  events: ReportRunEvent[]
}

export interface ReportRunsPage {
  runs: ReportRunListItem[]
  next_cursor: string | null
}

export interface ReportSchedule {
  id: string
  template_id: 'security-daily'
  template_revision: string
  parameters: { category?: 'security' | 'advisory' | 'vulnerability' | null }
  timezone: string
  cadence: 'daily' | 'weekly'
  local_time: string
  next_slot_at: string
  enabled: boolean
  created_at: string
}

export interface ReportSchedulesPage {
  schedules: ReportSchedule[]
  next_cursor: string | null
}

export interface CreateReportRun {
  template_id: ReportTemplateId
  parameters: Record<string, string | number | null>
  idempotency_key?: string
}

export interface CreateReportSchedule {
  template_id: 'security-daily'
  parameters: { category?: 'security' | 'advisory' | 'vulnerability' | null }
  timezone: string
  cadence: 'daily' | 'weekly'
  local_time: string
}

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) { super(message); this.name = 'ApiError' }
}

function qs(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value))
  }
  const str = search.toString()
  return str ? '?' + str : ''
}

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  if (!path.startsWith('/v1/') || path.startsWith('//')) throw new Error('Invalid API path')
  const response = await fetch(path, {
    method: 'GET',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    cache: 'no-store',
    signal: signal ?? null,
  })
  if (!response.ok) {
    const message = response.status === 401 || response.status === 403
      ? 'アクセス権限を確認してください。'
      : response.status === 404 ? '情報が見つかりません。'
      : response.status >= 500 ? 'APIに接続できません。時間をおいて再試行してください。'
      : 'データの取得に失敗しました。'
    throw new ApiError(response.status, message)
  }
  return await response.json() as T
}

async function mutation<T>(path: string, method: 'POST' | 'PUT' | 'PATCH', payload: object = {}): Promise<T> {
  if (!/^\/v1\/admin\//.test(path) || path.startsWith('//')) throw new Error('Invalid admin path')
  const response = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Nous-Admin-Action': '1' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) {
    const message = response.status === 409 ? '設定が競合しています。'
      : response.status === 422 ? '入力内容を確認してください。'
      : response.status === 401 || response.status === 403 ? '管理者権限を確認してください。'
      : response.status >= 500 ? '管理APIが利用できません。設定とDB接続を確認してください。'
      : '操作に失敗しました。'
    throw new ApiError(response.status, message)
  }
  return await response.json() as T
}

export const api = {
  items: (params: { q?: string | undefined; kind?: ItemKind | undefined; source?: string | undefined; limit?: number | undefined; cursor?: number | undefined }, signal?: AbortSignal) =>
    get<ItemPage>('/v1/items' + qs(params), signal),
  sources: (signal?: AbortSignal) => get<Source[]>('/v1/sources', signal),
  cve: (id: string, signal?: AbortSignal) => {
    if (!/^CVE-[0-9]{4}-[0-9]{4,}$/.test(id) || id.length > 64) throw new Error('Invalid CVE ID')
    return get<CveDetail>('/v1/cves/' + id, signal)
  },
  item: (id: number, signal?: AbortSignal) => get<ItemDetail>('/v1/items/' + id, signal),
  versions: (id: number, signal?: AbortSignal) => get<ItemVersion[]>('/v1/items/' + id + '/versions?limit=20', signal),
  adminSession: () => get<{ allowed: boolean }>('/v1/admin/session'),
  adminCatalog: () => get<CatalogEntry[]>('/v1/admin/catalog'),
  adminSources: () => get<ManagedSource[]>('/v1/admin/sources'),
  adminCreate: (source: SourceDefinition) => mutation<ManagedSource>('/v1/admin/sources', 'POST', source),
  adminUpdate: (id: string, source: SourceDefinition) =>
    mutation<ManagedSource>('/v1/admin/sources/' + encodeURIComponent(id), 'PUT', source),
  adminSettings: (id: string, settings: { enabled?: boolean; interval_minutes?: number; max_requests_per_hour?: number; max_concurrency?: number }) =>
    mutation<ManagedSource>('/v1/admin/sources/' + encodeURIComponent(id) + '/settings', 'PATCH', settings),
  adminProbe: (id: string) => mutation<ProbeResult>('/v1/admin/sources/' + encodeURIComponent(id) + '/probe', 'POST'),
  adminReportTemplates: () => get<ReportTemplate[]>('/v1/admin/report-templates'),
  adminReportRuns: (params: { limit?: number; cursor?: string } = {}) =>
    get<ReportRunsPage>('/v1/admin/report-runs' + qs(params)),
  adminReportRun: (id: string) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) throw new Error('Invalid report run ID')
    return get<ReportRun>('/v1/admin/report-runs/' + encodeURIComponent(id))
  },
  adminCreateReportRun: (request: CreateReportRun) =>
    mutation<{ run_id: string; state: ReportRunState }>('/v1/admin/report-runs', 'POST', request),
  adminReportSchedules: (params: { limit?: number; cursor?: string } = {}) =>
    get<ReportSchedulesPage>('/v1/admin/report-schedules' + qs(params)),
  adminCreateReportSchedule: (request: CreateReportSchedule) =>
    mutation<ReportSchedule>('/v1/admin/report-schedules', 'POST', request),
  adminUpdateReportSchedule: (id: string, changes: { enabled: boolean }) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) throw new Error('Invalid report schedule ID')
    return mutation<ReportSchedule>('/v1/admin/report-schedules/' + encodeURIComponent(id), 'PATCH', changes)
  },
  changes: (params: { since: string; kind?: ItemKind | undefined; limit?: number | undefined }, signal?: AbortSignal) =>
    get<ChangesPage>('/v1/changes' + qs(params), signal),
}
