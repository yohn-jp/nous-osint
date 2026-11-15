<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, type Item, type ItemKind, type Source } from '../lib/api'
import { kinds, kindLabel, dateLabel, stateLabel } from '../lib/presentation'

const route = useRoute()
const router = useRouter()
const term = ref('')
const kind = ref<ItemKind | null>(null)
const source = ref<string | null>(null)
const category = ref<string | null>(null)
const sources = ref<Source[]>([])
const sourceError = ref('')
const rows = ref<Item[]>([])
const nextCursor = ref<number | null>(null)
const loading = ref(false)
const loadingMore = ref(false)
const error = ref('')

const kindOptions = [{ label: 'すべての種別', value: null }, ...kinds]
const categories = [
  { label: '脆弱性データベース', value: 'vulnerability' },
  { label: '公式アドバイザリ', value: 'advisory' },
  { label: '脅威・攻撃調査', value: 'threat_research' },
  { label: 'セキュリティ動向', value: 'security_news' },
  { label: '企業・業界動向', value: 'industry' },
  { label: '求人情報', value: 'careers' },
]
const categoryOptions = computed(() => [{ label: 'すべてのカテゴリ', value: null }, ...categories.map(entry => ({
  ...entry, label: entry.label + ' · ' + sources.value.filter(row => row.category === entry.value).length,
}))])
const sourceOptions = computed(() => [{ label: 'すべての情報源', value: null },
  ...sources.value.map(entry => ({ label: entry.id, value: entry.id }))])
const hasAppliedFilters = computed(() => ['q', 'kind', 'source', 'category'].some(key => !!queryValue(route.query[key])))
const activeFilters = computed(() => [
  ...(queryValue(route.query.q) ? [{ key: 'q', label: '検索: ' + queryValue(route.query.q) }] : []),
  ...(queryValue(route.query.kind) ? [{ key: 'kind', label: '種別: ' + (kinds.find(row => row.value === queryValue(route.query.kind))?.label ?? queryValue(route.query.kind)) }] : []),
  ...(queryValue(route.query.source) ? [{ key: 'source', label: '情報源: ' + queryValue(route.query.source) }] : []),
  ...(queryValue(route.query.category) ? [{ key: 'category', label: 'カテゴリ: ' + (categories.find(row => row.value === queryValue(route.query.category))?.label ?? queryValue(route.query.category)) }] : []),
])
let request: AbortController | null = null
const sourceRequest = new AbortController()
let generation = 0

function queryValue(value: unknown): string { return typeof value === 'string' ? value : '' }
function parseKind(value: string): ItemKind | null { return kinds.find(entry => entry.value === value)?.value ?? null }
function categoryName(value: string) { return categories.find(entry => entry.value === value)?.label ?? value }

async function fetchSources() {
  try { sources.value = await api.sources(sourceRequest.signal) }
  catch (cause) {
    if (!(cause instanceof Error && cause.name === 'AbortError')) sourceError.value = '情報源を取得できません。種別と検索語での検索は利用できます。'
  }
}
void fetchSources()

async function loadPage(append = false) {
  if (append && (loading.value || loadingMore.value || nextCursor.value === null)) return
  if (!append) {
    request?.abort()
    generation++
    rows.value = []
    nextCursor.value = null
  }
  const token = generation
  const controller = new AbortController()
  request = controller
  if (append) loadingMore.value = true
  else loading.value = true
  error.value = ''
  try {
    const page = await api.items({
      q: queryValue(route.query.q).trim().slice(0, 200) || undefined,
      kind: parseKind(queryValue(route.query.kind)) ?? undefined,
      source: queryValue(route.query.source) || undefined,
      category: queryValue(route.query.category) || undefined,
      limit: 40,
      cursor: append ? nextCursor.value ?? undefined : undefined,
    }, controller.signal)
    if (token !== generation || controller.signal.aborted) return
    rows.value = append ? [...rows.value, ...page.items] : page.items
    nextCursor.value = page.next_cursor
  } catch (cause) {
    if (!controller.signal.aborted && token === generation)
      error.value = cause instanceof Error ? cause.message : '収集情報を取得できません。'
  } finally {
    if (token === generation) { loading.value = false; loadingMore.value = false }
  }
}
watch(() => [route.query.q, route.query.kind, route.query.source, route.query.category], () => {
  term.value = queryValue(route.query.q).slice(0, 200)
  kind.value = parseKind(queryValue(route.query.kind))
  source.value = queryValue(route.query.source) || null
  category.value = queryValue(route.query.category) || null
  void loadPage()
}, { immediate: true })

function applyFilters() {
  void router.replace({ name: 'explore', query: {
    ...(term.value.trim() ? { q: term.value.trim().slice(0, 200) } : {}),
    ...(kind.value ? { kind: kind.value } : {}),
    ...(source.value ? { source: source.value } : {}),
    ...(category.value ? { category: category.value } : {}),
  } })
}
function onSearchKeydown(event: KeyboardEvent) {
  if (event.isComposing || event.keyCode === 229) return
  event.preventDefault()
  applyFilters()
}
function clearFilters() { term.value = ''; kind.value = null; source.value = null; category.value = null; applyFilters() }
function removeFilter(key: string) {
  if (key === 'q') term.value = ''
  else if (key === 'kind') kind.value = null
  else if (key === 'source') source.value = null
  else if (key === 'category') category.value = null
  applyFilters()
}
function onShortcut(event: KeyboardEvent) {
  if (event.altKey || event.metaKey || event.ctrlKey || event.isComposing) return
  const target = event.target as HTMLElement | null
  if (target?.closest('input, textarea, select, [contenteditable="true"], [role="combobox"], [role="dialog"]')) return
  if (event.key === '/') {
    event.preventDefault()
    document.querySelector<HTMLInputElement>('.atlas-search-field input')?.focus()
    return
  }
  if (!['j', 'k', 'ArrowDown', 'ArrowUp'].includes(event.key) || !rows.value.length) return
  if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && !target?.closest('.atlas-results-list')) return
  if (target?.closest('a, button') && !target?.closest('.atlas-record-title')) return
  event.preventDefault()
  const current = rows.value.findIndex(item => 'atlas-record-' + item.id === document.activeElement?.id)
  const step = event.key === 'j' || event.key === 'ArrowDown' ? 1 : -1
  const index = Math.max(0, Math.min(rows.value.length - 1, current + step))
  document.getElementById('atlas-record-' + rows.value[index]?.id)?.focus({ preventScroll: false })
}
onMounted(() => window.addEventListener('keydown', onShortcut))
onBeforeUnmount(() => {
  request?.abort()
  sourceRequest.abort()
  window.removeEventListener('keydown', onShortcut)
})
</script>

<template>
  <q-page class="nous-page atlas-page explore-page">
    <header class="atlas-page-heading atlas-investigation-heading">
      <div class="atlas-heading-copy">
        <p class="atlas-kicker"><span class="atlas-kicker-mark" aria-hidden="true"></span> RESEARCH INDEX · OBSERVED RECORDS</p>
        <h1 class="atlas-title">収集記録を探す</h1>
        <p class="atlas-description">検索から一次資料、属性、出典、版の履歴へ。レコードは新しい観測版を示し、過去の観測は変更されません。</p>
      </div>
      <span class="atlas-key-hint"><kbd>/</kbd> 検索 <kbd>J</kbd><kbd>K</kbd> 移動</span>
    </header>

    <form class="atlas-search-form" role="search" aria-label="収集記録を検索" @submit.prevent="applyFilters">
      <label class="atlas-search-field">
        <q-icon name="search" aria-hidden="true" size="21px" />
        <q-input v-model="term" borderless dense maxlength="200" clearable
          placeholder="キーワード、CVE、組織名で検索" aria-label="検索キーワード" @keydown.enter="onSearchKeydown" />
        <kbd>Enter</kbd>
      </label>
      <div class="atlas-search-refine">
        <q-select v-model="category" dense borderless emit-value map-options :options="categoryOptions"
          aria-label="カテゴリ" class="atlas-filter-select" @update:model-value="applyFilters" />
        <q-select v-model="kind" dense borderless emit-value map-options :options="kindOptions"
          aria-label="種別" class="atlas-filter-select" @update:model-value="applyFilters" />
        <q-select v-model="source" dense borderless emit-value map-options :options="sourceOptions"
          aria-label="情報源" class="atlas-filter-select atlas-source-filter" @update:model-value="applyFilters" />
        <q-btn class="atlas-search-button" unelevated no-caps icon="arrow_forward" aria-label="検索を実行" @click="applyFilters" />
      </div>
    </form>

    <p v-if="sourceError" class="atlas-inline-notice" role="status">{{ sourceError }}</p>
    <div v-if="hasAppliedFilters" class="atlas-active-filters" aria-label="適用中の検索条件">
      <span>条件</span>
      <button v-for="filter in activeFilters" :key="filter.key" type="button" class="atlas-filter-chip"
        :aria-label="filter.label + ' を解除'" @click="removeFilter(filter.key)">
        {{ filter.label }} <q-icon name="close" size="14px" aria-hidden="true" />
      </button>
      <button type="button" class="atlas-clear-filters" @click="clearFilters">すべて解除</button>
    </div>

    <div class="atlas-results-heading" role="status" aria-live="polite">
      <div><span class="atlas-results-label">RECORD INDEX</span><h2>一致した記録</h2></div>
      <span v-if="!loading && !error">{{ rows.length }} 件を表示<span v-if="nextCursor !== null"> · 続きあり</span></span>
    </div>
    <div v-if="loading" class="atlas-results-skeleton" role="status" aria-label="検索結果を取得中">
      <q-skeleton v-for="index in 7" :key="index" type="rect" height="78px" class="atlas-skeleton-row" />
    </div>
    <div v-else-if="error && !rows.length" class="atlas-empty atlas-error" role="alert">
      <span class="atlas-empty-code">INDEX / UNAVAILABLE</span><h2>収集記録を取得できません</h2><p>{{ error }}</p>
      <q-btn outline no-caps label="再試行" @click="loadPage()" />
    </div>
    <div v-else-if="rows.length === 0" class="atlas-empty">
      <span class="atlas-empty-code">NO MATCHES</span>
      <h2>{{ hasAppliedFilters ? '条件に一致する記録がありません' : 'まだ収集記録がありません' }}</h2>
      <p>{{ hasAppliedFilters ? '検索語やカテゴリを変えて、別の記録を探してください。' : '情報源の取得状態を確認できます。' }}</p>
      <button v-if="hasAppliedFilters" type="button" @click="clearFilters">検索条件を解除する</button>
      <router-link v-else to="/sources">情報源の状態を見る <span aria-hidden="true">↗</span></router-link>
    </div>
    <ol v-else class="atlas-results-list" aria-label="収集レコード一覧">
      <li v-for="(item, index) in rows" :key="item.id" class="atlas-result-entry">
        <span class="atlas-result-index" aria-hidden="true">{{ String(index + 1).padStart(2, '0') }}</span>
        <div class="atlas-result-copy">
          <div class="atlas-result-meta">
            <span class="atlas-kind-label">{{ kindLabel(item.kind) }}</span>
            <span>{{ categoryName(sources.find(entry => entry.id === item.source)?.category ?? '') }}</span>
            <span>{{ item.organization || item.source }}</span>
          </div>
          <router-link :id="'atlas-record-' + item.id" class="atlas-record-title"
            :to="{ name: 'item', params: { id: item.id }, query: { returnTo: route.fullPath } }">
            {{ item.title }}
          </router-link>
          <div class="atlas-result-subline">
            <span>{{ item.source }}</span><span>公開 {{ dateLabel(item.published_at) }}</span>
          </div>
        </div>
        <div class="atlas-result-state">
          <span :data-state="item.state">{{ stateLabel[item.state] }}</span>
          <time :datetime="item.last_seen_at">観測 {{ dateLabel(item.last_seen_at) }}</time>
          <span class="atlas-version">v{{ item.current_version }}</span>
        </div>
        <router-link class="atlas-result-open" :to="{ name: 'item', params: { id: item.id }, query: { returnTo: route.fullPath } }"
          :aria-label="item.title + ' の記録を開く'"><q-icon name="arrow_outward" size="17px" aria-hidden="true" /></router-link>
      </li>
    </ol>
    <footer v-if="rows.length" class="atlas-list-footer">
      <q-btn v-if="nextCursor !== null" outline no-caps :loading="loadingMore" label="次の40件を表示" @click="loadPage(true)" />
      <span v-else>この条件で表示できる記録は以上です。</span>
      <span v-if="error" role="alert" class="atlas-list-error">{{ error }} <q-btn flat dense label="再試行" @click="loadPage(true)" /></span>
    </footer>
  </q-page>
</template>
