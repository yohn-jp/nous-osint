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
  const current = new AbortController()
  controller = current
  loading.value = true
  error.value = ''
  try {
    const result = await api.sources(current.signal)
    if (controller === current && !current.signal.aborted) sources.value = result
  } catch (e) {
    if (controller === current && !current.signal.aborted) {
      error.value = e instanceof Error ? e.message : '取得に失敗しました。'
    }
  } finally {
    if (controller === current) loading.value = false
  }
}
void load()
onBeforeUnmount(() => controller?.abort())
</script>

<template>
  <q-page class="nous-page sources-page">
    <div class="row items-center justify-between q-gutter-md"><h1 class="page-title q-ma-none">情報源</h1><div class="row q-gutter-sm"><q-btn v-if="canAdmin" color="primary" unelevated icon="tune" label="ソース管理" to="/admin/sources" /><q-btn flat color="primary" icon="add" label="公式カタログに提案" to="/sources/new" /></div></div>
    <p class="page-subtitle q-mb-xl">収集先の有効状態と最終成功日時。管理者はこのインスタンスへ直接追加できます。公式カタログへの提案はGitでレビューします。</p>
    <div v-if="!loading && !error" class="source-summary" role="status" aria-label="情報源の登録と状態">
      <div><span>登録</span><strong>{{ sources.length }}</strong></div>
      <div><span>設定有効</span><strong>{{ enabledCount }}</strong></div>
      <div><span>取得エラー</span><strong :class="{ 'text-negative': errorCount > 0 }">{{ errorCount }}</strong></div>
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
      <ul v-else class="source-register" aria-label="登録済みの情報源">
        <li v-for="entry in filtered" :key="entry.id" class="source-register-entry">
          <div class="source-register-identity">
            <div class="source-register-name">{{ entry.id }}</div>
            <div class="source-register-kind">{{ kindLabel(entry.item_kind) }} · {{ entry.kind.toUpperCase() }}</div>
          </div>
          <div class="source-register-state">
            <span class="source-state-label" :class="{ 'is-enabled': entry.enabled }">{{ entry.enabled ? '設定有効' : '設定停止' }}</span>
            <span class="source-state-caption">{{ entry.last_success_at ? '取得履歴あり' : '取得成功未確認' }}</span>
          </div>
          <div class="source-register-observation">
            <dl class="source-register-facts">
              <div><dt>最終成功</dt><dd>{{ dateLabel(entry.last_success_at) }}</dd></div>
              <div><dt>次回予定</dt><dd>{{ dateLabel(entry.next_due_at) }}</dd></div>
            </dl>
            <p v-if="entry.last_error" class="source-register-error">取得エラー: {{ entry.last_error }}</p>
          </div>
        </li>
      </ul>
    </section>
  </q-page>
</template>
