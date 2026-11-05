<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
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
const kindOptions = [{ label: 'すべての種別', value: null }, ...kinds]
const hasAppliedFilters = computed(() => ['q', 'kind', 'source'].some(key => !!queryValue(route.query[key])))
const sourceOptions = computed(() => [{ label: 'すべての情報源', value: null }, ...sources.value.map(s => ({ label: s.id, value: s.id }))])
const selectedId = computed(() => {
  const raw = typeof route.query.item === 'string' ? Number(route.query.item) : 0
  return Number.isSafeInteger(raw) && raw > 0 ? raw : null
})

function queryValue(value: unknown): string { return typeof value === 'string' ? value : '' }
function parseKind(value: string): ItemKind | null {
  return kinds.find(k => k.value === value)?.value ?? null
}
let request: AbortController | null = null
let sourceRequest: AbortController | null = new AbortController()
let generation = 0

async function fetchSources() {
  try { sources.value = await api.sources(sourceRequest?.signal) }
  catch (e) {
    if (!(e instanceof Error && e.name === 'AbortError')) sourceError.value = '情報源フィルタを取得できません。'
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
  } catch (e) {
    if (!controller.signal.aborted && token === generation) error.value = e instanceof Error ? e.message : '取得に失敗しました。'
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
function openItem(id: number) {
  if ($q.screen.width > 1250) {
    void router.replace({ name: 'explore', query: { ...route.query, item: String(id) } })
  } else {
    void router.push({ name: 'item', params: { id }, query: { returnTo: route.fullPath } })
  }
}
onBeforeUnmount(() => { request?.abort(); sourceRequest?.abort() })
</script>

<template>
  <q-page class="nous-page">
    <div class="row items-end justify-between q-mb-xl">
      <div><h1 class="page-title q-ma-none">探索</h1><div class="page-subtitle">公開情報を検索し、出典と変更履歴を確認します。</div></div>
    </div>

    <section aria-label="検索条件" class="content-panel search-panel q-pa-md q-mb-lg">
      <div class="row q-col-gutter-sm items-center search-fields">
        <div class="col-12 col-md">
          <q-input v-model="term" maxlength="200" outlined dense clearable placeholder="キーワードで検索" aria-label="キーワード検索" @keydown.enter="onSearchKeydown">
            <template #prepend><q-icon name="search" color="primary" /></template>
          </q-input>
        </div>
        <div class="col-6 col-md-3">
          <q-select v-model="kind" outlined dense emit-value map-options :options="kindOptions" label="種別" @update:model-value="applyFilters" />
        </div>
        <div class="col-6 col-md-3">
          <q-select v-model="source" outlined dense emit-value map-options :options="sourceOptions" label="情報源" @update:model-value="applyFilters" />
        </div>
        <div class="col-12 col-md-auto search-action">
          <q-btn class="search-submit-btn" color="primary" unelevated icon="search" label="検索" @click="applyFilters" />
        </div>
      </div>
      <div v-if="sourceError" class="text-caption text-negative q-mt-sm">{{ sourceError }}</div>
    </section>

    <div class="explore-grid">
      <section aria-label="検索結果" class="content-panel">
        <div class="row items-center justify-between q-px-lg q-py-md">
          <div class="results-heading"><strong>検索結果</strong><span v-if="!loading && !error" class="results-count" role="status" aria-live="polite">{{ rows.length }}件を表示{{ nextCursor !== null ? "（続きあり）" : "" }}</span></div>
          <q-btn v-if="hasAppliedFilters" flat no-caps size="sm" color="secondary" label="条件をクリア" @click="clearFilters" />
        </div>
        <q-separator />
        <div v-if="loading" class="q-pa-lg" aria-live="polite"><q-skeleton v-for="n in 4" :key="n" type="rect" height="62px" class="q-mb-lg" /></div>
        <div v-else-if="error" class="empty-state" role="alert">
          <q-icon name="error_outline" size="32px" color="negative" />
          <p>{{ error }}</p><q-btn outline color="primary" label="再試行" @click="loadPage()" />
        </div>
        <div v-else-if="rows.length === 0" class="empty-state result-empty-state">
          <div class="empty-heading">{{ hasAppliedFilters ? '条件に一致する情報はありません' : '収集済みの情報はまだありません' }}</div>
          <p>{{ hasAppliedFilters ? '検索語やフィルタを変えると、別の情報を探せます。' : '情報源の収集状態を確認できます。' }}</p>
          <q-btn v-if="hasAppliedFilters" flat no-caps color="primary" label="条件をクリア" @click="clearFilters" />
          <q-btn v-else flat no-caps color="primary" to="/sources" label="情報源を確認" />
        </div>
        <template v-else>
          <button v-for="item in rows" :key="item.id" type="button" class="result-row"
            :class="{ selected: selectedId === item.id }" :aria-pressed="selectedId === item.id" :aria-label="item.title + ' の詳細を開く'"
            @click="openItem(item.id)">
            <span class="result-title">{{ item.title }}</span>
            <span class="result-meta">
              <span class="kind-tag">{{ kindLabel(item.kind) }}</span>
              <span class="record-organization">{{ item.organization || item.source }}</span>
              <span class="meta-sep">{{ stateLabel[item.state] }}</span>
            </span>
            <span class="result-foot">{{ item.source }} · {{ dateLabel(item.published_at || item.last_seen_at) }} · v{{ item.current_version }}</span>
          </button>
          <div class="q-pa-md row items-center justify-center">
            <q-btn v-if="nextCursor !== null" outline color="primary" no-caps :loading="loadingMore" label="さらに読み込む" icon-right="expand_more" @click="loadPage(true)" />
            <span v-else class="text-caption text-grey-6">表示できる結果は以上です</span>
          </div>
          <div v-if="error" class="q-px-md q-pb-md text-negative" role="alert">{{ error }} <q-btn flat dense label="再試行" @click="loadPage(true)" /></div>
        </template>
      </section>
      <aside class="content-panel preview-pane" aria-label="情報のプレビュー">
        <ItemPreview v-if="selectedId" :item-id="selectedId" compact />
        <div v-else class="preview-empty"><q-icon name="article" size="27px" aria-hidden="true" /><p>一覧から情報を選択してください。</p><span>出典と観測履歴をここに表示します。</span></div>
      </aside>
    </div>
  </q-page>
</template>
