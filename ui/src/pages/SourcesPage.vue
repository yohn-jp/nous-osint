<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue'
import { api, type Source } from '../lib/api'
import { dateLabel, kindLabel } from '../lib/presentation'

const sources = ref<Source[]>([])
const loading = ref(false)
const error = ref('')
const textFilter = ref('')
const filtered = computedSources()
let controller: AbortController | null = null

function computedSources() {
  // Computation stays local: the source registry is small and read only.
  return { get value() { return sources.value.filter(s => s.id.toLowerCase().includes(textFilter.value.toLowerCase())).sort((a,b) => a.id.localeCompare(b.id)) } }
}
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
  <q-page class="nous-page">
    <div class="eyebrow q-mb-sm">INTELLIGENCE / SOURCES</div>
    <h1 class="page-title q-ma-none">情報源を確認する。</h1>
    <p class="page-subtitle q-mb-xl">収集先の有効状態と最終成功日時。変更操作は提供していません。</p>
    <section class="content-panel">
      <div class="row items-center q-pa-md q-gutter-sm">
        <q-input v-model="textFilter" dense outlined clearable label="情報源を絞り込む" class="col" style="max-width: 370px"><template #prepend><q-icon name="search" /></template></q-input>
        <q-space /><q-btn flat dense icon="refresh" color="primary" aria-label="再読み込み" @click="load" />
      </div>
      <q-separator />
      <div v-if="loading" class="q-pa-lg" aria-live="polite"><q-skeleton v-for="n in 3" :key="n" type="QItem" class="q-mb-md" /></div>
      <div v-else-if="error" class="empty-state" role="alert"><q-icon name="error_outline" color="negative" size="30px"/><p>{{ error }}</p><q-btn outline color="primary" label="再試行" @click="load" /></div>
      <div v-else-if="filtered.value.length === 0" class="empty-state"><q-icon name="rss_feed" size="32px"/><p class="q-mt-md">該当する情報源がありません。</p></div>
      <div v-for="entry in filtered.value" v-else :key="entry.id" class="result-row" style="cursor: default">
        <div class="row items-start justify-between q-gutter-sm">
          <div><div class="text-weight-bold" style="overflow-wrap: anywhere">{{ entry.id }}</div><div class="result-foot">{{ kindLabel(entry.item_kind) }} · {{ entry.kind.toUpperCase() }}</div></div>
          <q-badge :color="entry.enabled ? 'positive' : 'grey-6'" :label="entry.enabled ? '収集有効' : '収集停止'" />
        </div>
        <div class="result-foot">最終成功: {{ dateLabel(entry.last_success_at) }}　/　次回予定: {{ dateLabel(entry.next_due_at) }}</div>
        <div v-if="entry.last_error" class="text-negative text-caption q-mt-sm">取得エラー: {{ entry.last_error }}</div>
      </div>
    </section>
  </q-page>
</template>
