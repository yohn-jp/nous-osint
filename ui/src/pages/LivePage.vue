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
const categoryOptions = [{ label: 'すべての観測', value: null }, ...categories]
const categoryName = (value: string) => categories.find(row => row.value === value)?.label ?? value
const sourceOptions = computed(() => [
  { label: 'すべての情報源', value: null },
  ...sources.value.filter(source => source.category !== 'careers' &&
    (!selectedCategory.value || source.category === selectedCategory.value))
    .map(source => ({ label: source.id, value: source.id })),
])
const latestObservation = computed(() => records.value[0]?.observed_at ?? null)
const filterLabel = computed(() => categoryName(selectedCategory.value ?? 'すべての観測'))
const dayGroups = computed(() => {
  const groups: { key: string; label: string; rows: StreamObservation[] }[] = []
  for (const row of records.value) {
    const parts = new Intl.DateTimeFormat('ja-JP', {
      timeZone: 'Asia/Tokyo', year: 'numeric', month: 'long', day: 'numeric', weekday: 'short',
    }).formatToParts(new Date(row.observed_at))
    const part = (type: string) => parts.find(value => value.type === type)?.value ?? ''
    const key = `${part('year')}-${part('month')}-${part('day')}`
    let group = groups.at(-1)
    if (!group || group.key !== key) {
      group = { key, label: `${part('month')} ${part('day')}日 · ${part('weekday')}曜日`, rows: [] }
      groups.push(group)
    }
    group.rows.push(row)
  }
  return groups
})

let request: AbortController | null = null
let olderRequest: AbortController | null = null
let sourceController: AbortController | null = null
let generation = 0
let interval: ReturnType<typeof setInterval> | null = null

function queryValue(value: unknown): string { return typeof value === 'string' ? value : '' }
function updateFilters() {
  void router.replace({ name: 'live', query: {
    ...(selectedCategory.value ? { category: selectedCategory.value } : {}),
    ...(selectedSource.value ? { source: selectedSource.value } : {}),
  } })
}
function updateCategory() {
  if (selectedSource.value && sources.value.find(source => source.id === selectedSource.value)?.category !== selectedCategory.value)
    selectedSource.value = null
  updateFilters()
}
function platformLabel(platform: StreamObservation['platform']) {
  return platform === 'bluesky' ? 'BLUESKY' : platform === 'x' ? 'X'
    : platform === 'rss' ? 'RSS / ATOM' : platform === 'json_api' ? 'JSON API' : 'WEB'
}
function timeLabel(value: string) {
  return new Intl.DateTimeFormat('ja-JP', {
    timeZone: 'Asia/Tokyo', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).format(new Date(value))
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
  const controller = new AbortController()
  olderRequest = controller
  loadingMore.value = true
  try {
    const page = await api.stream({
      category: queryValue(route.query.category) || undefined,
      source: queryValue(route.query.source) || undefined,
      limit: 40, cursor: nextCursor.value,
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
  sourceController = new AbortController()
  try { sources.value = await api.sources(sourceController.signal) }
  catch (cause) {
    if (!(cause instanceof Error && cause.name === 'AbortError'))
      sourceError.value = '発信源一覧を読み込めませんでした。観測記録の閲覧は続けられます。'
  }
  interval = setInterval(() => {
    if (autoRefresh.value && document.visibilityState === 'visible' && !loading.value && !loadingMore.value)
      void loadLatest(false)
  }, 60_000)
})
onBeforeUnmount(() => {
  request?.abort(); olderRequest?.abort(); sourceController?.abort()
  if (interval !== null) clearInterval(interval)
})
</script>

<template>
  <q-page class="nous-page atlas-page live-page">
    <header class="atlas-page-heading">
      <div class="atlas-heading-copy">
        <p class="atlas-kicker"><span class="atlas-kicker-mark" aria-hidden="true"></span> OBSERVATIONS · PUBLIC SOURCES</p>
        <h1 class="atlas-title">観測記録</h1>
        <p class="atlas-description">公開情報がNousに記録された順に並びます。見出しから収集記録と出典をたどれます。</p>
      </div>
      <div class="atlas-feed-actions">
        <q-toggle v-model="autoRefresh" dense color="primary" label="60秒ごとに確認" aria-label="60秒ごとに自動確認" />
        <q-btn flat no-caps icon="refresh" label="今すぐ確認" :loading="loading" @click="loadLatest(true)" />
      </div>
    </header>

    <section class="atlas-feed-status" role="status" aria-live="polite">
      <span class="atlas-status-glyph" :class="{ 'is-paused': !autoRefresh }" aria-hidden="true"></span>
      <span>{{ autoRefresh ? '自動確認中' : '自動確認を停止中' }}</span>
      <span class="atlas-status-divider" aria-hidden="true"></span>
      <span>最終確認 <time v-if="lastChecked" :datetime="lastChecked">{{ dateLabel(lastChecked) }}</time><span v-else>—</span></span>
      <span class="atlas-status-divider" aria-hidden="true"></span>
      <span>最新記録 <time v-if="latestObservation" :datetime="latestObservation">{{ dateLabel(latestObservation) }}</time><span v-else>—</span></span>
    </section>

    <section class="atlas-filter-strip" aria-label="観測を絞り込む">
      <span class="atlas-filter-label">表示範囲</span>
      <q-select v-model="selectedCategory" dense borderless emit-value map-options :options="categoryOptions"
        aria-label="カテゴリ" class="atlas-filter-select" @update:model-value="updateCategory" />
      <span class="atlas-filter-divider" aria-hidden="true"></span>
      <q-select v-model="selectedSource" dense borderless emit-value map-options :options="sourceOptions"
        aria-label="発信源" class="atlas-filter-select atlas-source-filter" @update:model-value="updateFilters" />
      <span class="atlas-filter-result">{{ filterLabel }} · {{ records.length }}件</span>
    </section>

    <p v-if="sourceError" class="atlas-inline-notice" role="status">{{ sourceError }}</p>
    <div v-if="pendingNew > 0" class="atlas-new-observations" role="status">
      <span>先頭40件に {{ pendingNew }} 件の新しい観測があります。現在の位置は維持しています。</span>
      <q-btn flat no-caps color="primary" label="先頭に移動" @click="loadLatest(true)" />
    </div>

    <div v-if="loading && records.length === 0" class="atlas-stream-skeleton" role="status" aria-label="観測情報を取得中">
      <q-skeleton v-for="index in 6" :key="index" type="rect" height="86px" class="atlas-skeleton-row" />
    </div>
    <div v-else-if="error && !records.length" class="atlas-empty atlas-error" role="alert">
      <span class="atlas-empty-code">FEED / UNAVAILABLE</span><h2>観測記録を取得できません</h2><p>{{ error }}</p>
      <q-btn outline no-caps label="再試行" @click="loadLatest(true)" />
    </div>
    <div v-else-if="!records.length" class="atlas-empty">
      <span class="atlas-empty-code">NO OBSERVATIONS</span><h2>条件に合う観測記録はありません</h2>
      <p>条件を変えるか、情報源の取得状態を確認してください。</p>
      <router-link to="/sources">情報源の状態を見る <span aria-hidden="true">↗</span></router-link>
    </div>

    <div v-else class="observation-ledger" aria-label="観測記録一覧">
      <section v-for="group in dayGroups" :key="group.key" class="observation-day" :aria-labelledby="'day-' + group.key">
        <div class="observation-day-rail"><h2 :id="'day-' + group.key">{{ group.label }}</h2><span>{{ group.rows.length }}件</span></div>
        <ol class="observation-list">
          <li v-for="observation in group.rows" :key="observation.observation_id" class="observation-entry"
            :class="{ 'observation-entry-updated': observation.change === 'updated' }">
            <div class="observation-time">
              <time :datetime="observation.observed_at">{{ timeLabel(observation.observed_at) }}</time>
              <span>{{ observation.change === 'updated' ? '更新' : '新規' }}</span>
            </div>
            <div class="observation-main">
              <div class="observation-source-line">
                <span class="observation-platform">{{ platformLabel(observation.platform) }}</span>
                <span class="observation-source-name">{{ observation.organization || observation.source }}</span>
                <span class="observation-source-id">{{ observation.source }}</span>
              </div>
              <router-link class="observation-title" :to="{ name: 'item', params: { id: observation.item_id }, query: { returnTo: route.fullPath } }">
                {{ observation.title }}
              </router-link>
              <div class="observation-meta">
                <span class="observation-category">{{ categoryName(observation.category) }}</span>
                <span>公開 {{ dateLabel(observation.published_at) }}</span>
                <span class="observation-entry-actions">
                  <a v-if="safeExternalUrl(observation.url)" :href="safeExternalUrl(observation.url)"
                    target="_blank" rel="noopener noreferrer">発信元 <q-icon name="north_east" size="13px" aria-hidden="true" /></a>
                  <router-link :to="{ name: 'item', params: { id: observation.item_id }, query: { returnTo: route.fullPath } }">証跡を確認 <span aria-hidden="true">→</span></router-link>
                </span>
              </div>
            </div>
            <span class="observation-change-mark" aria-hidden="true"></span>
          </li>
        </ol>
      </section>
    </div>
    <footer v-if="records.length" class="atlas-list-footer">
      <q-btn v-if="nextCursor !== null" outline no-caps :loading="loadingMore" label="過去の観測を読み込む" @click="loadOlder" />
      <span v-else>この条件で表示できる観測は以上です。</span>
      <span v-if="error" role="alert" class="atlas-list-error">{{ error }}</span>
    </footer>
  </q-page>
</template>
