<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, type Change, type ItemKind } from '../lib/api'
import { kinds, kindLabel, dateLabel } from '../lib/presentation'

const route = useRoute()
const router = useRouter()
const windowDays = ref(7)
const kind = ref<ItemKind | null>(null)
const changes = ref<Change[]>([])
const loading = ref(false)
const error = ref('')
const windows = [{ label: '過去7日', value: 7 }, { label: '過去30日', value: 30 }, { label: '過去90日', value: 90 }]
const kindsOptions = [{ label: 'すべての種別', value: null }, ...kinds]
let controller: AbortController | null = null
let requestId = 0
const queryText = (v: unknown) => typeof v === 'string' ? v : ''

function apply() {
  void router.replace({
    name: 'changes',
    query: { days: String(windowDays.value), ...(kind.value ? { kind: kind.value } : {}) },
  })
}
async function load() {
  controller?.abort()
  controller = new AbortController()
  const id = ++requestId
  loading.value = true
  changes.value = []
  error.value = ''
  try {
    const since = new Date(Date.now() - windowDays.value * 86400000).toISOString()
    const result = await api.changes({ since, kind: kind.value ?? undefined, limit: 100 }, controller.signal)
    if (id === requestId && !controller.signal.aborted) changes.value = result.changes
  } catch (e) {
    if (!controller.signal.aborted && id === requestId) error.value = e instanceof Error ? e.message : '取得に失敗しました。'
  } finally { if (id === requestId) loading.value = false }
}
watch(() => [route.query.days, route.query.kind], () => {
  const days = Number(queryText(route.query.days) || '7')
  windowDays.value = [7, 30, 90].includes(days) ? days : 7
  kind.value = kinds.find(k => k.value === queryText(route.query.kind))?.value ?? null
  void load()
}, { immediate: true })
onBeforeUnmount(() => controller?.abort())
</script>

<template>
  <q-page class="nous-page">
    <h1 class="page-title q-ma-none">変更履歴</h1>
    <p class="page-subtitle q-mb-xl">観測された新規・更新レコードを時系列で確認する。</p>
    <section class="content-panel">
      <div class="row q-col-gutter-sm items-center q-pa-md">
        <div class="col-6 col-sm-3"><q-select v-model="windowDays" :options="windows" dense outlined emit-value map-options label="対象期間" @update:model-value="apply" /></div>
        <div class="col-6 col-sm-3"><q-select v-model="kind" :options="kindsOptions" dense outlined emit-value map-options label="種別" @update:model-value="apply" /></div>
        <q-space /><q-btn flat dense icon="refresh" color="primary" aria-label="再読み込み" @click="load" />
      </div>
      <q-separator />
      <div v-if="loading" class="q-pa-lg" aria-live="polite"><q-skeleton v-for="n in 3" :key="n" type="rect" height="62px" class="q-mb-md" /></div>
      <div v-else-if="error" class="empty-state" role="alert"><q-icon name="error_outline" color="negative" size="30px"/><p>{{ error }}</p><q-btn outline color="primary" label="再試行" @click="load" /></div>
      <div v-else-if="changes.length === 0" class="empty-state"><q-icon name="history" size="32px"/><p class="q-mt-md">この期間に記録された変更はありません。</p></div>
      <template v-else>
        <router-link v-for="change in changes" :key="change.item_id + ':' + change.version" class="result-row" :to="{ name: 'item', params: { id: change.item_id } }">
          <div class="result-meta"><span class="kind-tag">{{ kindLabel(change.kind) }}</span><span>{{ change.version === 1 ? '初回観測' : '改訂 v' + change.version }}</span></div>
          <div class="result-title">{{ change.title }}</div>
          <div class="result-foot">{{ dateLabel(change.observed_at) }}</div>
        </router-link>
        <div class="text-caption text-grey-6 q-px-lg q-py-md">最大100件を表示。期間を短くすると絞り込めます。</div>
      </template>
    </section>
  </q-page>
</template>
