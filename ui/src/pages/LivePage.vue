<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, type Source, type StreamObservation } from '../lib/api'
import { dateLabel, safeExternalUrl } from '../lib/presentation'

const route = useRoute()
const router = useRouter()
const records = ref<StreamObservation[]>([])
const sources = ref<Source[]>([])
const loading = ref(true)
const loadingMore = ref(false)
const error = ref('')
const sourceError = ref('')
const nextCursor = ref<number | null>(null)
const pendingNew = ref(0)
const lastChecked = ref<string | null>(null)
const autoRefresh = ref(true)
const selectedCategory = ref<string | null>(null)
const selectedSource = ref<string | null>(null)

const categories = [
  { label: '脅威・攻撃調査', value: 'threat_research' },
  { label: '公式アドバイザリ', value: 'advisory' },
  { label: '脆弱性データベース', value: 'vulnerability' },
  { label: 'セキュリティ動向', value: 'security_news' },
  { label: '企業・業界動向', value: 'industry' },
]
const categoryOptions = [{ label: 'セキュリティ全件', value: null }, ...categories]
const sourceOptions = computed(() => [
  { label: 'すべての発信源', value: null },
  ...sources.value
    .filter(s => s.category !== 'careers' &&
      (!selectedCategory.value || s.category === selectedCategory.value))
    .map(s => ({ label: s.id, value: s.id })),
])
const totalVisible = computed(() => records.value.length)
const latestObservation = computed(() => records.value[0]?.observed_at ?? null)
const filterLabel = computed(() => categories.find(c => c.value === selectedCategory.value)?.label ?? '全カテゴリ')
let request: AbortController | null = null
let olderRequest: AbortController | null = null
let generation = 0
let interval: ReturnType<typeof setInterval> | null = null

function queryValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
}
function updateFilters() {
  void router.replace({
    name: 'live',
    query: {
      ...(selectedCategory.value ? { category: selectedCategory.value } : {}),
      ...(selectedSource.value ? { source: selectedSource.value } : {}),
    },
  })
}
function updateCategory() {
  // A selected source may belong to a different category.
  if (selectedSource.value &&
      sources.value.find(s => s.id === selectedSource.value)?.category !== selectedCategory.value)
    selectedSource.value = null
  updateFilters()
}

async function loadLatest(install = true) {
  request?.abort()
  const controller = new AbortController()
  request = controller
  const token = generation
  if (install) loading.value = true
  error.value = ''
  try {
    const page = await api.stream({
      category: queryValue(route.query.category) || undefined,
      source: queryValue(route.query.source) || undefined,
      limit: 40,
    }, controller.signal)
    if (controller.signal.aborted || token !== generation) return
    lastChecked.value = new Date().toISOString()
    if (install || records.value.length === 0) {
      records.value = page.observations
      nextCursor.value = page.next_cursor
      pendingNew.value = 0
    } else {
      const head = records.value[0]?.observation_id ?? 0
      pendingNew.value = page.observations.filter(row => row.observation_id > head).length
    }
  } catch (cause) {
    if (!controller.signal.aborted && token === generation)
      error.value = cause instanceof Error ? cause.message : '新着情報を取得できませんでした。'
  } finally {
    if (token === generation && !controller.signal.aborted) loading.value = false
  }
}

async function loadOlder() {
  if (loading.value || loadingMore.value || nextCursor.value === null) return
  const token = generation
  const cursor = nextCursor.value
  const controller = new AbortController()
  olderRequest = controller
  loadingMore.value = true
  try {
    const page = await api.stream({
      category: queryValue(route.query.category) || undefined,
      source: queryValue(route.query.source) || undefined,
      limit: 40, cursor,
    }, controller.signal)
    if (controller.signal.aborted || token !== generation) return
    const seen = new Set(records.value.map(row => row.observation_id))
    records.value = [...records.value, ...page.observations.filter(row => !seen.has(row.observation_id))]
    nextCursor.value = page.next_cursor
  } catch (cause) {
    if (!controller.signal.aborted && token === generation)
      error.value = cause instanceof Error ? cause.message : '過去の観測を取得できませんでした。'
  } finally {
    if (token === generation) loadingMore.value = false
  }
}
watch(() => [route.query.category, route.query.source], () => {
  generation++
  olderRequest?.abort()
  selectedCategory.value = queryValue(route.query.category) || null
  selectedSource.value = queryValue(route.query.source) || null
  records.value = []
  loadingMore.value = false
  nextCursor.value = null
  pendingNew.value = 0
  void loadLatest(true)
}, { immediate: true })

onMounted(async () => {
  const controller = new AbortController()
  sourceController = controller
  try {
    sources.value = await api.sources(controller.signal)
  } catch (cause) {
    if (!(cause instanceof Error && cause.name === 'AbortError'))
      sourceError.value = '発信源一覧を読み込めませんでした。Feed自体は利用できます。'
  }
  interval = setInterval(() => {
    if (autoRefresh.value && document.visibilityState === 'visible' && !loading.value &&
        !loadingMore.value) void loadLatest(false)
  }, 60_000)
})
let sourceController: AbortController | null = null
onBeforeUnmount(() => {
  request?.abort()
  olderRequest?.abort()
  sourceController?.abort()
  if (interval !== null) clearInterval(interval)
})
</script>

<template>
  <q-page class="nous-page live-page">
    <header class="live-heading">
      <div class="live-heading-copy">
        <p class="workstation-overline">INTELLIGENCE <span aria-hidden="true">/</span> SOURCE SIGNALS</p>
        <h1 class="page-title">Live Intelligence</h1>
        <p class="page-subtitle">研究者・一次発信源の公開情報を、Nousで観測した順に表示します。翻訳・要約・脅威度の推測は行いません。</p>
      </div>
      <div class="live-heading-actions">
        <q-btn unelevated no-caps color="primary" icon="refresh" label="最新を確認"
          :loading="loading" @click="loadLatest(true)" />
        <q-toggle v-model="autoRefresh" dense label="自動確認 / 60秒" color="primary" />
      </div>
    </header>
    <div class="live-monitor" role="status" aria-live="polite">
      <span class="live-monitor-dot" :class="{ 'is-paused': !autoRefresh }" aria-hidden="true"></span>
      <span>{{ autoRefresh ? '60秒ごとに新着を確認' : '自動確認は停止中' }}</span>
      <span class="live-monitor-separator" aria-hidden="true"></span>
      <span>最終確認: {{ dateLabel(lastChecked) }}</span>
      <span class="live-monitor-separator" aria-hidden="true"></span>
      <span>最新の収集観測: {{ dateLabel(latestObservation) }}</span>
    </div>

    <section class="live-filters" aria-label="発信源の絞り込み">
      <q-select v-model="selectedCategory" dense outlined emit-value map-options
        :options="categoryOptions" label="対象カテゴリ" @update:model-value="updateCategory" />
      <q-select v-model="selectedSource" dense outlined emit-value map-options
        :options="sourceOptions" label="発信源"
        @update:model-value="updateFilters" />
      <span class="live-filter-note">速報性の順位付けではありません。到着した観測記録を新しい順に掲載します。</span>
    </section>
    <p v-if="sourceError" class="text-warning" role="status">{{ sourceError }}</p>
    <div v-if="pendingNew > 0" class="live-pending" role="status">
      <span>新しい観測があります（先頭40件中 {{ pendingNew }} 件）。閲覧中の位置は変更していません。</span>
      <q-btn unelevated no-caps color="primary" label="新着を表示" @click="loadLatest(true)" />
    </div>
    <div class="live-stream-header">
      <div><span class="live-stream-label">OBSERVATION STREAM</span>
        <h2>新着・更新</h2></div>
      <span>{{ filterLabel }} · {{ totalVisible }} 件表示</span>
    </div>
    <div v-if="loading && records.length === 0" class="live-skeleton" role="status" aria-label="観測情報を取得中">
      <q-skeleton v-for="n in 6" :key="n" type="rect" height="95px" class="q-mb-sm" />
    </div>
    <div v-else-if="error && !records.length" class="workstation-message" role="alert">
      <strong>Live Feedに接続できません</strong>
      <p>{{ error }}</p><q-btn outline no-caps color="primary" label="再試行" @click="loadLatest(true)" />
    </div>
    <div v-else-if="!records.length" class="workstation-message">
      <strong>該当する観測はまだありません</strong>
      <p>収集が未開始か、選択した条件で新しい情報が見つかっていません。情報源の稼働状態をご確認ください。</p>
      <q-btn outline no-caps color="primary" to="/sources" label="情報源の状態" />
    </div>
    <ol v-else class="live-stream-list">
      <li v-for="observation in records" :key="observation.observation_id" class="live-entry">
        <div class="live-entry-rail">
          <span class="live-entry-marker" :class="{ 'is-update': observation.change === 'updated' }"></span>
        </div>
        <article class="live-entry-content">
          <div class="live-entry-headline">
            <div class="live-entry-origin">
              <span class="live-entry-platform">{{ observation.platform === 'bluesky' ? 'BLUESKY' :
                observation.platform === 'rss' ? 'RSS / ATOM' : observation.platform.toUpperCase() }}</span>
              <span class="live-entry-author">{{ observation.organization || observation.source }}</span>
              <span class="live-entry-change">{{ observation.change === 'new' ? '新規' : '更新' }}</span>
            </div>
            <time class="live-entry-observed" :datetime="observation.observed_at">
              観測 {{ dateLabel(observation.observed_at) }}
            </time>
          </div>
          <h3 class="live-entry-title">{{ observation.title }}</h3>
          <div class="live-entry-bottom">
            <span>発信 {{ dateLabel(observation.published_at) }}</span>
            <span class="live-entry-separator" aria-hidden="true">/</span>
            <span>{{ observation.source }}</span>
            <span class="live-entry-separator" aria-hidden="true">/</span>
            <span>{{ observation.category }}</span>
            <a v-if="safeExternalUrl(observation.url)" class="live-entry-direct"
              :href="safeExternalUrl(observation.url)" target="_blank" rel="noopener noreferrer">
              原文を開く <q-icon name="open_in_new" size="14px" />
            </a>
            <router-link class="live-entry-detail" :to="{ name: 'item', params: { id: observation.item_id },
              query: { returnTo: '/live' } }">記録と根拠</router-link>
          </div>
        </article>
      </li>
    </ol>
    <div v-if="records.length" class="live-list-footer">
      <q-btn v-if="nextCursor !== null" outline no-caps color="primary"
        :loading="loadingMore" label="さらに40件を表示" @click="loadOlder" />
      <span v-else>これ以上の記録はありません</span>
      <span v-if="error" class="text-negative" role="alert">{{ error }}</span>
    </div>
  </q-page>
</template>
