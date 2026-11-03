import type { ItemKind, ItemState } from './api'

export const kinds: { label: string; value: ItemKind }[] = [
  { label: 'ニュース', value: 'news' },
  { label: '脆弱性', value: 'vulnerability' },
  { label: 'アドバイザリ', value: 'advisory' },
  { label: '企業動向', value: 'company_update' },
  { label: '求人', value: 'job_posting' },
]
export const kindLabel = (kind: ItemKind): string => kinds.find(x => x.value === kind)?.label ?? kind
export const stateLabel: Record<ItemState, string> = {
  current: '現行', unknown: '未確認', stale: '更新確認待ち', closed: '終了',
}
const dateFormatter = new Intl.DateTimeFormat('ja-JP', {
  timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit',
})
export function dateLabel(value: string | null | undefined): string {
  if (!value) return '記録なし'
  const time = new Date(value)
  return Number.isNaN(time.getTime()) ? '日時不明' : dateFormatter.format(time) + ' JST'
}
export function safeValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  return text.length > 600 ? text.slice(0, 600) + '…' : text
}
