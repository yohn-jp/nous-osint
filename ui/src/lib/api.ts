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
    signal,
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

export const api = {
  items: (params: { q?: string; kind?: ItemKind; source?: string; limit?: number; cursor?: number }, signal?: AbortSignal) =>
    get<ItemPage>('/v1/items' + qs(params), signal),
  sources: (signal?: AbortSignal) => get<Source[]>('/v1/sources', signal),
  item: (id: number, signal?: AbortSignal) => get<ItemDetail>('/v1/items/' + id, signal),
  versions: (id: number, signal?: AbortSignal) => get<ItemVersion[]>('/v1/items/' + id + '/versions', signal),
  changes: (params: { since: string; kind?: ItemKind; limit?: number }, signal?: AbortSignal) =>
    get<ChangesPage>('/v1/changes' + qs(params), signal),
}
