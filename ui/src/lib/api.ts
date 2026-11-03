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
    const message = response.status === 409 ? 'ソースIDまたは設定が競合しています。'
      : response.status === 422 ? 'ソース定義または接続検証に失敗しました。'
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
  changes: (params: { since: string; kind?: ItemKind | undefined; limit?: number | undefined }, signal?: AbortSignal) =>
    get<ChangesPage>('/v1/changes' + qs(params), signal),
}
