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
  <q-page class="nous-page changes-page changes-workstation">
    <header class="workstation-heading">
      <div>
        <p class="workstation-overline">LIBRARY <span aria-hidden="true">/</span> OBSERVATION HISTORY</p>
        <h1 class="page-title">変更履歴</h1>
        <p class="page-subtitle">収集情報の新規観測と版の更新を、観測日時順に確認します。</p>
      </div>
    </header>
    <section class="content-panel changes-register" aria-label="観測イベント一覧">
      <div class="changes-controls">
        <q-select v-model="windowDays" :options="windows" dense outlined emit-value map-options
          label="対象期間" class="changes-filter" @update:model-value="apply" />
        <q-select v-model="kind" :options="kindsOptions" dense outlined emit-value map-options
          label="種別" class="changes-filter" @update:model-value="apply" />
        <q-space />
        <q-btn flat round dense icon="refresh" color="primary" aria-label="履歴を再取得" :loading="loading" @click="load" />
      </div>
      <div v-if="!loading && !error" class="changes-ledger-summary" role="status" aria-live="polite">
        <span>観測イベント</span><strong>{{ changes.length }} 件</strong><span>取得上限100件</span>
      </div>
      <div v-if="loading" class="workstation-loading" role="status" aria-label="履歴を取得中">
        <q-skeleton v-for="n in 6" :key="n" type="rect" height="42px" class="q-mb-sm" />
      </div>
      <div v-else-if="error" class="workstation-message" role="alert">
        <strong>観測履歴を取得できませんでした</strong><p>{{ error }}</p>
        <q-btn outline color="primary" no-caps label="再取得" @click="load" />
      </div>
      <div v-else-if="changes.length === 0" class="workstation-message">
        <strong>この期間の観測イベントはありません</strong>
        <p>取得できた範囲に新規観測・版の更新はありません。情報源の取得状態も確認できます。</p>
        <q-btn flat no-caps to="/sources" label="情報源を確認" color="primary" />
      </div>
      <div v-else class="changes-table-scroll">
        <table class="changes-table">
          <caption class="workstation-sr-only">直近の新規観測と改訂。項目名から元のレコードへ移動できます。</caption>
          <thead><tr>
            <th scope="col">観測日時</th>
            <th scope="col">対象レコード</th>
            <th scope="col">分類</th>
            <th scope="col">版</th>
          </tr></thead>
          <tbody>
            <tr v-for="change in changes" :key="change.item_id + ':' + change.version">
              <td class="changes-date"><time :datetime="change.observed_at">{{ dateLabel(change.observed_at) }}</time></td>
              <td class="changes-title">
                <router-link :to="{ name: 'item', params: { id: change.item_id }, query: { returnTo: route.fullPath } }">
                  {{ change.title }}
                </router-link>
              </td>
              <td><span class="changes-kind">{{ kindLabel(change.kind) }}</span></td>
              <td class="changes-version">{{ change.version === 1 ? '初回観測' : 'v' + change.version }}</td>
            </tr>
          </tbody>
        </table>
        <div class="changes-table-note">最大100件のAPI応答を表示します。対象期間と種別はURLに保持されます。</div>
      </div>
    </section>
  </q-page>
</template>
