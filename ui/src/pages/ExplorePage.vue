<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useQuasar } from 'quasar'
import { useRoute, useRouter } from 'vue-router'
import ItemPreview from '../components/ItemPreview.vue'
import { api, type Item, type ItemKind, type Source } from '../lib/api'
import { kinds, kindLabel, stateLabel, dateLabel } from '../lib/presentation'

const route = useRoute()
const router = useRouter()
const $q = useQuasar()
const term = ref('')
const kind = ref<ItemKind | null>(null)
const source = ref<string | null>(null)
const sources = ref<Source[]>([])
const sourceError = ref('')
const rows = ref<Item[]>([])
const nextCursor = ref<number | null>(null)
const loading = ref(false)
const loadingMore = ref(false)
const error = ref('')
const density = ref<'compact' | 'standard'>('compact')
const inspectorOpen = ref(true)
const inspectorWidth = ref(396)
const kindOptions = [{ label: 'すべての種別', value: null }, ...kinds]
const sourceOptions = computed(() => [
  { label: 'すべての情報源', value: null },
  ...sources.value.map(s => ({ label: s.id, value: s.id })),
])

function queryValue(value: unknown): string { return typeof value === 'string' ? value : '' }
function parseKind(value: string): ItemKind | null {
  return kinds.find(k => k.value === value)?.value ?? null
}
const hasAppliedFilters = computed(() => ['q', 'kind', 'source'].some(key => !!queryValue(route.query[key])))
const selectedId = computed(() => {
  const raw = typeof route.query.item === 'string' ? Number(route.query.item) : 0
  return Number.isSafeInteger(raw) && raw > 0 ? raw : null
})
const activeRecordId = computed(() => inspectorOpen.value
  ? (selectedId.value ?? rows.value[0]?.id ?? null)
  : null)
const activeFilters = computed(() => [
  ...(queryValue(route.query.q) ? [{ key: 'q', label: '検索: ' + queryValue(route.query.q) }] : []),
  ...(queryValue(route.query.kind) ? [{ key: 'kind', label: '種別: ' + (kinds.find(k => k.value === queryValue(route.query.kind))?.label ?? queryValue(route.query.kind)) }] : []),
  ...(queryValue(route.query.source) ? [{ key: 'source', label: '情報源: ' + queryValue(route.query.source) }] : []),
])
let request: AbortController | null = null
const sourceRequest = new AbortController()
let generation = 0
let resizeCleanup: (() => void) | null = null

async function fetchSources() {
  try { sources.value = await api.sources(sourceRequest.signal) }
  catch (cause) {
    if (!(cause instanceof Error && cause.name === 'AbortError')) sourceError.value = '情報源を取得できません。種別と検索語は利用できます。'
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
      limit: 40,
      cursor: append ? nextCursor.value ?? undefined : undefined,
    }, controller.signal)
    if (token !== generation || controller.signal.aborted) return
    rows.value = append ? [...rows.value, ...page.items] : page.items
    nextCursor.value = page.next_cursor
  } catch (cause) {
    if (!controller.signal.aborted && token === generation) {
      error.value = cause instanceof Error ? cause.message : '収集情報を取得できません。'
    }
  } finally {
    if (token === generation) { loading.value = false; loadingMore.value = false }
  }
}
watch(() => [route.query.q, route.query.kind, route.query.source], () => {
  term.value = queryValue(route.query.q).slice(0, 200)
  kind.value = parseKind(queryValue(route.query.kind))
  source.value = queryValue(route.query.source) || null
  void loadPage()
}, { immediate: true })
watch(() => route.query.item, () => { if (selectedId.value !== null) inspectorOpen.value = true })

function applyFilters() {
  void router.replace({
    name: 'explore',
    query: {
      ...(term.value.trim() ? { q: term.value.trim().slice(0, 200) } : {}),
      ...(kind.value ? { kind: kind.value } : {}),
      ...(source.value ? { source: source.value } : {}),
    },
  })
}
function onSearchKeydown(event: KeyboardEvent) {
  if (event.isComposing || event.keyCode === 229) return
  event.preventDefault()
  applyFilters()
}
function clearFilters() { term.value = ''; kind.value = null; source.value = null; applyFilters() }
function removeFilter(key: string) {
  if (key === 'q') term.value = ''
  else if (key === 'kind') kind.value = null
  else if (key === 'source') source.value = null
  applyFilters()
}
function openItem(id: number) {
  if ($q.screen.width >= 1200) {
    inspectorOpen.value = true
    void router.replace({ name: 'explore', query: { ...route.query, item: String(id) } })
  } else {
    void router.push({ name: 'item', params: { id }, query: { returnTo: route.fullPath } })
  }
}
function closeInspector() {
  inspectorOpen.value = false
  if (route.query.item) {
    const query = { ...route.query }
    delete query.item
    void router.replace({ name: 'explore', query })
  }
}
function toggleDensity() {
  density.value = density.value === 'compact' ? 'standard' : 'compact'
  try { localStorage.setItem('nous-record-density', density.value) } catch { /* private mode */ }
}
function onShortcut(event: KeyboardEvent) {
  if (event.altKey || event.metaKey || event.ctrlKey || event.isComposing) return
  const target = event.target as HTMLElement | null
  if (target?.closest('input, textarea, select, [contenteditable="true"], [role="combobox"], [role="dialog"]')) return
  if (event.key === '/') {
    event.preventDefault()
    document.getElementById('nous-search-input')?.focus()
    return
  }
  if ($q.screen.width < 1200 || rows.value.length === 0) return
  if (event.key === 'Escape' && inspectorOpen.value) { event.preventDefault(); closeInspector(); return }
  if (event.key !== 'j' && event.key !== 'k' && event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
  event.preventDefault()
  const currentIndex = rows.value.findIndex(row => row.id === activeRecordId.value)
  const step = event.key === 'j' || event.key === 'ArrowDown' ? 1 : -1
  const index = Math.max(0, Math.min(rows.value.length - 1, currentIndex + step))
  const id = rows.value[index]?.id
  if (id === undefined) return
  openItem(id)
  void nextTick(() => document.getElementById('nous-record-' + id)?.focus({ preventScroll: false }))
}
function resizeKeydown(event: KeyboardEvent) {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return
  event.preventDefault()
  inspectorWidth.value = Math.max(300, Math.min(640, inspectorWidth.value + (event.key === 'ArrowLeft' ? 24 : -24)))
}
function startResize(event: PointerEvent) {
  if (event.button !== 0) return
  const fromX = event.clientX
  const fromWidth = inspectorWidth.value
  const move = (next: PointerEvent) => {
    inspectorWidth.value = Math.max(300, Math.min(640, fromWidth + fromX - next.clientX))
  }
  const stop = () => {
    window.removeEventListener('pointermove', move)
    window.removeEventListener('pointerup', stop)
    window.removeEventListener('pointercancel', stop)
    resizeCleanup = null
  }
  resizeCleanup?.()
  resizeCleanup = stop
  window.addEventListener('pointermove', move)
  window.addEventListener('pointerup', stop)
  window.addEventListener('pointercancel', stop)
}
onMounted(() => {
  try {
    const stored = localStorage.getItem('nous-record-density')
    if (stored === 'standard' || stored === 'compact') density.value = stored
  } catch { /* private mode */ }
  window.addEventListener('keydown', onShortcut)
})
onBeforeUnmount(() => {
  request?.abort()
  sourceRequest.abort()
  resizeCleanup?.()
  window.removeEventListener('keydown', onShortcut)
})
</script>

<template>
  <q-page class="nous-page explore-page workstation-page">
    <header class="workstation-heading">
      <div>
        <p class="workstation-overline">LIBRARY <span aria-hidden="true">/</span> OBSERVATIONS</p>
        <h1 class="page-title">収集情報を調べる</h1>
        <p class="page-subtitle">検索、出典、観測履歴を一つの作業面で確認します。</p>
      </div>
      <span class="workstation-key-hint" aria-label="キーボード操作：スラッシュで検索、JとKでレコード移動">/ 検索 &nbsp; J K 移動</span>
    </header>

    <section class="workstation-query" role="search" aria-label="収集情報を検索">
      <div class="workstation-search-box">
        <q-icon name="search" aria-hidden="true" size="19px" />
        <q-input id="nous-search-input" v-model="term" borderless dense maxlength="200"
          clearable placeholder="キーワード、CVE、企業名を検索" aria-label="検索キーワード"
          class="workstation-query-input" @keydown.enter="onSearchKeydown" />
      </div>
      <q-select v-model="kind" dense outlined emit-value map-options :options="kindOptions" label="種別"
        class="workstation-select" @update:model-value="applyFilters" />
      <q-select v-model="source" dense outlined emit-value map-options :options="sourceOptions" label="情報源"
        class="workstation-select workstation-source-select" @update:model-value="applyFilters" />
      <q-btn unelevated no-caps color="primary" label="検索" class="workstation-search-submit" @click="applyFilters" />
    </section>

    <div v-if="sourceError" class="workstation-inline-warning" role="status">{{ sourceError }}</div>
    <div v-if="hasAppliedFilters" class="workstation-filters" aria-label="適用中の検索条件">
      <span>適用中</span>
      <button v-for="filter in activeFilters" :key="filter.key" type="button" class="workstation-filter"
        :aria-label="filter.label + ' を解除'" @click="removeFilter(filter.key)">
        {{ filter.label }} <q-icon name="close" size="14px" aria-hidden="true" />
      </button>
      <button type="button" class="workstation-clear" @click="clearFilters">すべて解除</button>
    </div>

    <div class="workstation-split" :class="{ 'inspector-hidden': !inspectorOpen }"
      :style="{ '--inspector-width': inspectorWidth + 'px' }">
      <section aria-label="収集レコード一覧" class="workstation-ledger">
        <div class="workstation-toolbar">
          <div class="workstation-count" role="status" aria-live="polite">
            <strong>収集レコード</strong>
            <span v-if="!loading && !error">{{ rows.length }} 件表示{{ nextCursor !== null ? ' / 続きあり' : '' }}</span>
          </div>
          <div class="workstation-toolbar-actions">
            <q-btn flat dense no-caps :icon="density === 'compact' ? 'view_agenda' : 'view_headline'"
              :label="density === 'compact' ? '標準表示' : '高密度表示'" @click="toggleDensity" />
            <q-btn v-if="$q.screen.width >= 1200" flat dense no-caps
              :icon="inspectorOpen ? 'vertical_split' : 'dock_to_right'"
              :label="inspectorOpen ? '詳細を閉じる' : '詳細を表示'"
              :aria-pressed="inspectorOpen" @click="inspectorOpen ? closeInspector() : inspectorOpen = true" />
          </div>
        </div>
        <div v-if="loading" class="workstation-loading" role="status" aria-label="検索結果を取得中">
          <q-skeleton v-for="n in 7" :key="n" type="rect" height="45px" class="q-mb-sm" />
        </div>
        <div v-else-if="error && rows.length === 0" class="workstation-message" role="alert">
          <strong>収集情報を取得できませんでした</strong><p>{{ error }}</p>
          <q-btn outline no-caps color="primary" label="再試行" @click="loadPage()" />
        </div>
        <div v-else-if="rows.length === 0" class="workstation-message">
          <strong>{{ hasAppliedFilters ? '一致する情報がありません' : 'まだ収集済みの情報がありません' }}</strong>
          <p>{{ hasAppliedFilters ? '検索語または条件を変更してください。' : '情報源の収集状態を確認できます。' }}</p>
          <q-btn v-if="hasAppliedFilters" flat no-caps color="primary" label="条件を解除" @click="clearFilters" />
          <q-btn v-else flat no-caps color="primary" to="/sources" label="情報源へ移動" />
        </div>
        <template v-else>
          <div class="workstation-table-scroll">
            <table class="workstation-table" :class="'density-' + density">
              <caption class="workstation-sr-only">収集レコード。タイトルを選ぶと詳細と出典を表示します。</caption>
              <thead><tr>
                <th scope="col" class="col-record">レコード</th>
                <th scope="col" class="col-source">情報源</th>
                <th scope="col" class="col-observed">公開・観測</th>
                <th scope="col" class="col-state">状態</th>
              </tr></thead>
              <tbody>
                <tr v-for="(item, index) in rows" :key="item.id" :class="{ 'is-active': activeRecordId === item.id }">
                  <td class="col-record">
                    <div class="workstation-record-cell">
                      <span class="workstation-row-index" aria-hidden="true">{{ String(index + 1).padStart(2, '0') }}</span>
                      <div class="workstation-record-main">
                        <span class="workstation-kind">{{ kindLabel(item.kind) }}</span>
                        <button :id="'nous-record-' + item.id" type="button" class="workstation-record-link"
                          :title="item.title" :aria-pressed="activeRecordId === item.id"
                          @click="openItem(item.id)">{{ item.title }}</button>
                        <span class="workstation-record-mobile-meta">{{ item.organization || item.source }} · {{ dateLabel(item.published_at || item.last_seen_at) }}</span>
                      </div>
                    </div>
                  </td>
                  <td class="col-source"><span class="workstation-org">{{ item.organization || item.source }}</span><span v-if="item.organization && item.organization !== item.source" class="workstation-source-id">{{ item.source }}</span></td>
                  <td class="col-observed"><time :datetime="item.published_at || item.last_seen_at">{{ dateLabel(item.published_at || item.last_seen_at) }}</time><span class="workstation-date-type">{{ item.published_at ? '公開' : '最終観測' }}</span></td>
                  <td class="col-state"><span class="workstation-state" :data-state="item.state">{{ stateLabel[item.state] }}</span><span class="workstation-version">v{{ item.current_version }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="workstation-list-footer">
            <q-btn v-if="nextCursor !== null" outline no-caps color="primary" :loading="loadingMore" label="続きの40件を読み込む" icon-right="expand_more" @click="loadPage(true)" />
            <span v-else>表示できるレコードは以上です</span>
            <span v-if="error" class="text-negative" role="alert">{{ error }} <q-btn flat dense label="再試行" @click="loadPage(true)" /></span>
          </div>
        </template>
      </section>

      <template v-if="inspectorOpen">
        <div class="workstation-resizer" role="separator" tabindex="0" aria-orientation="vertical"
          aria-label="詳細ペインの幅を調整" aria-valuemin="300" aria-valuemax="640" :aria-valuenow="inspectorWidth"
          @pointerdown="startResize" @keydown="resizeKeydown"><span aria-hidden="true"></span></div>
        <aside class="workstation-inspector" aria-label="選択したレコードの根拠">
          <div class="workstation-inspector-heading">
            <span>RECORD INSPECTOR</span>
            <q-btn flat round dense icon="close" aria-label="詳細ペインを閉じる" @click="closeInspector" />
          </div>
          <ItemPreview v-if="activeRecordId" :item-id="activeRecordId" compact />
          <div v-else class="workstation-message"><strong>レコードを選択</strong><p>タイトルを選ぶと出典と変更履歴が表示されます。</p></div>
        </aside>
      </template>
    </div>
  </q-page>
</template>
