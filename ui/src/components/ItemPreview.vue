<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api, type ItemDetail, type ItemVersion } from '../lib/api'
import { dateLabel, kindLabel, safeExternalUrl, safeValue, stateLabel } from '../lib/presentation'

const route = useRoute()
const props = withDefaults(defineProps<{ itemId: number; compact?: boolean }>(), { compact: false })
const item = ref<ItemDetail | null>(null)
const versions = ref<ItemVersion[]>([])
const tab = ref<'summary' | 'metadata' | 'history'>('summary')
const cveIds = computed(() => {
  if (!item.value) return []
  const structured = item.value.attributes?.vulnerability
  const fromStructured = (structured && typeof structured === 'object' && !Array.isArray(structured))
    ? (structured as Record<string, unknown>).cve_id : null
  const ids = [
    ...(typeof fromStructured === 'string' ? [fromStructured] : []),
    ...(item.value.title.match(/CVE-[0-9]{4}-[0-9]{4,}/g) ?? []),
  ]
  return [...new Set(ids.filter(value => /^CVE-[0-9]{4}-[0-9]{4,}$/.test(value) && value.length <= 64))].slice(0, 12)
})
const loading = ref(false)
const error = ref('')
let controller: AbortController | null = null
let epoch = 0

async function load() {
  controller?.abort()
  const current = ++epoch
  controller = new AbortController()
  item.value = null
  versions.value = []
  error.value = ''
  if (!Number.isSafeInteger(props.itemId) || props.itemId <= 0) { error.value = '不正な項目IDです。'; loading.value = false; return }
  loading.value = true
  try {
    const [detail, history] = await Promise.all([
      api.item(props.itemId, controller.signal),
      api.versions(props.itemId, controller.signal),
    ])
    if (epoch !== current || controller.signal.aborted) return
    item.value = detail
    versions.value = history.slice(0, 20)
  } catch (e) {
    if (!controller.signal.aborted && epoch === current) error.value = e instanceof Error ? e.message : '取得に失敗しました。'
  } finally {
    if (epoch === current) loading.value = false
  }
}
watch(() => props.itemId, () => { tab.value = 'summary'; void load() }, { immediate: true })
onBeforeUnmount(() => controller?.abort())
</script>

<template>
  <div class="q-pa-lg item-preview">
    <div v-if="loading" aria-live="polite"><q-skeleton type="text" width="60%" /><q-skeleton type="text" height="64px" /><q-skeleton type="text" width="85%" /></div>
    <div v-else-if="error" role="alert" class="text-center q-py-lg">
      <q-icon name="error_outline" color="negative" size="28px" />
      <p class="q-mt-sm">{{ error }}</p><q-btn outline color="primary" label="再試行" @click="load" />
    </div>
    <template v-else-if="item">
      <div class="eyebrow q-mb-md">{{ kindLabel(item.kind) }} / {{ stateLabel[item.state] }}</div>
      <h2 class="q-ma-none detail-title" :class="compact ? 'text-h6' : 'text-h5'">{{ item.title }}</h2>
      <div class="text-caption text-grey-6 q-mt-md">{{ item.organization || item.source }}</div>
      <div class="inspector-actions">
        <q-btn unelevated no-caps color="primary" icon-right="open_in_new" :href="safeExternalUrl(item.url)"
          :disable="!safeExternalUrl(item.url)" target="_blank" rel="noopener noreferrer" label="一次情報を開く" />
        <q-btn v-if="compact" flat dense no-caps color="primary" icon-right="open_in_full"
          :to="{ name: 'item', params: { id: props.itemId }, query: { returnTo: route.fullPath } }" label="詳細ページ" />
      </div>
      <q-tabs v-model="tab" dense no-caps align="justify" active-color="primary" indicator-color="primary"
        class="inspector-tabs" aria-label="レコード詳細の項目">
        <q-tab name="summary" label="概要" />
        <q-tab name="metadata" label="属性と出典" />
        <q-tab name="history" label="観測履歴" />
      </q-tabs>
      <section v-if="tab === 'summary' && cveIds.length" class="detail-section">
        <div class="text-subtitle2 q-mb-sm">CVEとKEVの関連情報</div>
        <div class="row q-gutter-sm">
          <q-btn v-for="cve in cveIds" :key="cve" outline dense no-caps
            color="primary" icon-right="open_in_new" :label="cve + ' / KEV'"
            :to="{ path: '/cves/' + cve, query: { returnTo: route.fullPath } }" />
        </div>
        <div class="text-caption text-grey-7 q-mt-sm">
          CVEへの言及だけでは悪用確認を意味しません。CISA KEVとの対応は別途確認します。
        </div>
      </section>
      <section v-if="tab === 'summary'" class="detail-section">
        <div class="text-subtitle2 q-mb-sm">出典と記録</div>
        <div class="kv-line"><div class="kv-key">情報源</div><div>{{ item.source }}</div></div>
        <div class="kv-line"><div class="kv-key">公開日時</div><div>{{ dateLabel(item.published_at) }}</div></div>
        <div class="kv-line"><div class="kv-key">初回取得</div><div>{{ dateLabel(item.first_seen_at) }}</div></div>
        <div class="kv-line"><div class="kv-key">最終確認</div><div>{{ dateLabel(item.last_seen_at) }}</div></div>
        <div class="kv-line"><div class="kv-key">現在版</div><div>v{{ item.current_version }}</div></div>
      </section>
      <section v-if="tab === 'metadata' && Object.keys(item.attributes).length" class="detail-section">
        <div class="text-subtitle2 q-mb-sm">属性</div>
        <div v-for="[key, value] in Object.entries(item.attributes)" :key="key" class="kv-line">
          <div class="kv-key">{{ key }}</div><div>{{ safeValue(value) }}</div>
        </div>
      </section>
      <section v-if="tab === 'metadata'" class="detail-section">
        <div class="text-subtitle2 q-mb-sm">出典メタデータ</div>
        <div v-for="[key, value] in Object.entries(item.provenance)" :key="key" class="kv-line">
          <div class="kv-key">{{ key }}</div><div>{{ safeValue(value) }}</div>
        </div>
        <div v-if="!Object.keys(item.provenance).length" class="text-caption text-grey-6">出典メタデータがありません。</div>
      </section>
      <section v-if="tab === 'history'" class="detail-section">
        <div class="text-subtitle2 q-mb-sm">観測履歴 <span class="text-caption text-grey-6 q-ml-sm">最近の {{ versions.length }} 件</span></div>
        <q-list dense separator>
          <q-item v-for="version in versions" :key="version.version" class="q-px-none">
            <q-item-section>
              <q-item-label>v{{ version.version }} <span class="text-caption text-grey-6">· {{ dateLabel(version.observed_at) }}</span></q-item-label>
              <q-item-label caption class="ellipsis">SHA-256: {{ version.sha256 }}</q-item-label>
            </q-item-section>
          </q-item>
        </q-list>
        <div v-if="versions.length === 0" class="text-caption text-grey-6">観測履歴はありません。</div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.inspector-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 16px 0 13px; }
.inspector-actions .q-btn { min-height: 40px; }
.inspector-tabs { border-block: 1px solid var(--nous-line); margin-inline: -4px; }
.inspector-tabs .q-tab { min-height: 43px; padding-inline: 6px; }
.detail-section h3, .detail-section .text-subtitle2 { color: var(--nous-ink); font-weight: 740; }
</style>
