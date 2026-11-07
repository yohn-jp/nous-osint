<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { api, type Source } from '../lib/api'
import { dateLabel, kindLabel } from '../lib/presentation'

const sources = ref<Source[]>([])
const loading = ref(false)
const error = ref('')
const textFilter = ref('')
const statusFilter = ref<'all' | 'enabled' | 'disabled' | 'error'>('all')
const statusOptions = [
  { label: 'すべての状態', value: 'all' },
  { label: '設定: 有効', value: 'enabled' },
  { label: '設定: 停止', value: 'disabled' },
  { label: '取得エラーあり', value: 'error' },
]
const enabledCount = computed(() => sources.value.filter(s => s.enabled).length)
const errorCount = computed(() => sources.value.filter(s => !!s.last_error).length)
const canAdmin = ref(false)
void api.adminSession().then(session => { canAdmin.value = session.allowed }).catch(() => { canAdmin.value = false })
const filtered = computed(() => sources.value
  .filter(s => s.id.toLowerCase().includes(textFilter.value.trim().toLowerCase()))
  .filter(s => statusFilter.value === 'all' ||
    (statusFilter.value === 'enabled' && s.enabled) ||
    (statusFilter.value === 'disabled' && !s.enabled) ||
    (statusFilter.value === 'error' && !!s.last_error))
  .sort((a, b) => a.id.localeCompare(b.id)))
let controller: AbortController | null = null
async function load() {
  controller?.abort()
  controller = new AbortController()
  loading.value = true
  error.value = ''
  try { sources.value = await api.sources(controller.signal) }
  catch (e) { if (!controller.signal.aborted) error.value = e instanceof Error ? e.message : '取得に失敗しました。' }
  finally { loading.value = false }
}
void load()
onBeforeUnmount(() => controller?.abort())
</script>

<template>
  <q-page class="nous-page sources-page">
    <div class="row items-center justify-between q-gutter-md"><h1 class="page-title q-ma-none">情報源</h1><div class="row q-gutter-sm"><q-btn v-if="canAdmin" color="primary" unelevated icon="tune" label="ソース管理" to="/admin/sources" /><q-btn flat color="primary" icon="add" label="公式カタログに提案" to="/sources/new" /></div></div>
    <p class="page-subtitle q-mb-xl">収集先の有効状態と最終成功日時。管理者はこのインスタンスへ直接追加できます。公式カタログへの提案はGitでレビューします。</p>
    <div v-if="!loading && !error" class="source-summary" role="status" aria-label="取得対象の集計">
      <div><span>登録済み</span><strong>{{ sources.length }}</strong></div>
      <div><span>設定: 有効</span><strong>{{ enabledCount }}</strong></div>
      <div><span>取得エラーあり</span><strong :class="{ 'text-negative': errorCount > 0 }">{{ errorCount }}</strong></div>
    </div>
    <section class="content-panel">
      <div class="row items-center q-pa-md q-gutter-sm">
        <q-input v-model="textFilter" dense outlined clearable label="情報源を絞り込む" class="col" style="max-width: 370px"><template #prepend><q-icon name="search" /></template></q-input>
        <q-select v-model="statusFilter" dense outlined emit-value map-options
          :options="statusOptions" label="設定・取得状態" class="source-status-filter" />
        <q-space /><q-btn flat dense icon="refresh" color="primary" aria-label="再読み込み" @click="load" />
      </div>
      <q-separator />
      <div v-if="loading" class="q-pa-lg" aria-live="polite"><q-skeleton v-for="n in 3" :key="n" type="rect" height="62px" class="q-mb-md" /></div>
      <div v-else-if="error" class="empty-state" role="alert"><q-icon name="error_outline" color="negative" size="30px"/><p>{{ error }}</p><q-btn outline color="primary" label="再試行" @click="load" /></div>
      <div v-else-if="filtered.length === 0" class="empty-state"><q-icon name="rss_feed" size="32px"/><p class="q-mt-md">{{ sources.length ? '条件に一致する情報源がありません。' : '登録済みの情報源がありません。' }}</p><q-btn v-if="sources.length" flat color="primary" no-caps label="絞り込みを解除" @click="textFilter = ''; statusFilter = 'all'" /></div>
      <template v-else><div v-for="entry in filtered" :key="entry.id" class="result-row source-observation-row">
        <div class="row items-start justify-between q-gutter-sm">
          <div><div class="text-weight-bold" style="overflow-wrap: anywhere">{{ entry.id }}</div><div class="result-foot">{{ kindLabel(entry.item_kind) }} · {{ entry.kind.toUpperCase() }}</div></div>
          <q-badge :color="entry.enabled ? 'positive' : 'grey-6'" :label="entry.enabled ? '設定: 有効' : '設定: 停止'" />
        </div>
        <div class="source-observation-dates"><span>最終成功 <strong>{{ dateLabel(entry.last_success_at) }}</strong></span><span>次回予定 <strong>{{ dateLabel(entry.next_due_at) }}</strong></span></div>
        <div v-if="entry.last_error" class="text-negative text-caption q-mt-sm">取得エラー: {{ entry.last_error }}</div>
      </div></template>
    </section>
  </q-page>
</template>
