<script setup lang="ts">
import { ref, computed, watch, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import { api, type CveDetail } from '../lib/api'
import { dateLabel, safeExternalUrl } from '../lib/presentation'

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const backTarget = computed(() => {
  const candidate = route.query.returnTo
  return typeof candidate === 'string' &&
    (/^\/explore(?:\?[^#]*)?$/.test(candidate) ||
     /^\/items\/[1-9][0-9]*(?:\?[^#]*)?$/.test(candidate)) &&
    !candidate.includes('\\') ? candidate : '/explore'
})
const backLabel = computed(() => backTarget.value.startsWith('/items/') ? '元のレコードへ戻る' : '探索へ戻る')
const data = ref<CveDetail | null>(null)
const loading = ref(false)
const error = ref('')
let controller: AbortController | null = null
let generation = 0

async function load() {
  controller?.abort()
  const current = ++generation
  controller = new AbortController()
  error.value = ''
  data.value = null
  if (!/^CVE-[0-9]{4}-[0-9]{4,}$/.test(id.value) || id.value.length > 64) {
    error.value = 'CVE識別子の形式が正しくありません。'
    return
  }
  loading.value = true
  try {
    const result = await api.cve(id.value, controller.signal)
    if (current === generation && !controller.signal.aborted) data.value = result
  } catch (e) {
    if (current === generation && !controller.signal.aborted) {
      error.value = e instanceof Error ? e.message : '取得に失敗しました。'
    }
  } finally {
    if (current === generation) loading.value = false
  }
}
watch(id, () => { void load() }, { immediate: true })
onBeforeUnmount(() => controller?.abort())
const kevStatus = computed(() => data.value?.kev.status === 'listed'
  ? 'KEV掲載を確認' : data.value?.kev.status === 'not_listed'
    ? '最新KEVに掲載なし' : 'KEV掲載状況は未確認')
</script>

<template>
  <q-page class="nous-page cve-page">
    <q-btn class="q-mb-md" flat no-caps icon="arrow_back" color="secondary"
      :label="backLabel" :to="backTarget" />
    <h1 class="page-title q-ma-none">{{ id }}</h1>
    <p class="page-subtitle">CVE識別子を軸に、複数の一次情報とCISAの悪用確認情報を結び付けます。</p>
    <section class="content-panel q-mt-lg q-pa-lg" style="max-width: 980px">
      <div v-if="loading" aria-live="polite"><q-skeleton type="text" width="60%" /><q-skeleton height="96px" type="rect" /></div>
      <div v-else-if="error" role="alert">
        <div class="text-negative">{{ error }}</div>
        <q-btn flat color="primary" label="再試行" @click="load" />
      </div>
      <template v-else-if="data">
        <div class="cve-status-block row items-center justify-between q-gutter-md">
          <div>
            <div class="eyebrow">CISA KEV掲載状況</div>
            <div class="text-h6 q-mt-sm">{{ kevStatus }}</div>
          </div>
          <q-badge :color="data.kev.status === 'listed' ? 'negative' : 'grey-7'"
            :label="data.kev.status === 'listed' ? 'KEV掲載' : data.kev.status === 'not_listed' ? '掲載なし' : '未確認'" />
        </div>
        <p class="text-caption text-grey-7 q-mt-md q-mb-none">
          KEVの最終正常取得: {{ dateLabel(data.kev.catalog_as_of) }}。
          <span v-if="!data.kev.catalog_fresh">データが未取得または古い場合、掲載が見つからなくても未掲載とは断定しません。</span>
          <span v-else>未掲載判定は直近48時間以内に完全なKEVカタログを取得できた場合だけです。</span>
        </p>
        <section v-if="data.kev.status === 'listed'" class="detail-section">
          <div class="text-subtitle2 q-mb-sm">CISAの確認内容</div>
          <div class="kv-line"><div class="kv-key">提供元</div><div>{{ data.kev.vendor || '—' }}</div></div>
          <div class="kv-line"><div class="kv-key">製品</div><div>{{ data.kev.product || '—' }}</div></div>
          <div class="kv-line"><div class="kv-key">KEV登録日</div><div>{{ data.kev.date_added || '—' }}</div></div>
          <div class="kv-line"><div class="kv-key">対応期限</div><div>{{ data.kev.due_date || '—' }}</div></div>
          <div class="kv-line"><div class="kv-key">ランサムウェアでの既知の利用</div><div>{{ data.kev.known_ransomware_campaign_use || '未確認' }}</div></div>
          <div class="q-mt-md">
            <q-btn outline color="primary" no-caps icon-right="open_in_new"
              label="CISAの情報源" :href="safeExternalUrl(data.kev.source_url || '')"
              target="_blank" rel="noopener noreferrer" />
          </div>
        </section>
        <section class="detail-section">
          <div class="text-subtitle2 q-mb-md">このCVEに関連する収集済み情報</div>
          <p class="text-caption text-grey-7">
            「KEV」はCISAの掲載証拠、「CVEレコード」は構造化識別子、
            「タイトル中の言及」は単なる参照を意味します。異なる意味を混同しません。
          </p>
          <div v-if="!data.references.length" class="text-grey-7 text-caption q-py-md">
            Nousにはまだ関連する収集済みレコードがありません。
          </div>
          <q-list v-else separator>
            <q-item v-for="row in data.references" :key="row.item_id" class="q-px-none">
              <q-item-section>
                <q-item-label class="text-weight-medium">{{ row.title }}</q-item-label>
                <q-item-label caption>{{ row.source }} · {{ row.relation === 'kev' ? 'CISA KEV' :
                    row.relation === 'record' ? 'CVEレコード' :
                    row.relation === 'reference' ? '構造化参照' : 'タイトル中の言及' }}
                  · {{ dateLabel(row.last_seen_at) }}</q-item-label>
                <q-item-label caption class="q-mt-xs cve-reference-source">{{ row.source_url }}</q-item-label>
              </q-item-section>
              <q-item-section side>
                <q-btn flat dense color="primary" icon="chevron_right" :to="{ name: 'item', params: { id: row.item_id }, query: { returnTo: route.fullPath } }"
                  :aria-label="row.title + 'の記録を開く'" />
              </q-item-section>
            </q-item>
          </q-list>
          <p v-if="data.references_truncated" class="text-caption text-grey-7 q-mt-md">
            関連レコードが50件を超えています。表示は50件までです。
          </p>
        </section>
        <div class="q-mt-lg">
          <q-btn flat color="primary" no-caps icon-right="open_in_new"
            :href="safeExternalUrl(data.canonical_url)" target="_blank"
            rel="noopener noreferrer" label="CVE Programの識別子ページ" />
        </div>
      </template>
    </section>
  </q-page>
</template>
