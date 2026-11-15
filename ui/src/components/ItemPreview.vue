<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api, type ItemDetail, type ItemVersion } from '../lib/api'
import { dateLabel, kindLabel, safeExternalUrl, safeValue, stateLabel } from '../lib/presentation'

const route = useRoute()
const props = defineProps<{ itemId: number }>()
const item = ref<ItemDetail | null>(null)
const versions = ref<ItemVersion[]>([])
const tab = ref<'overview' | 'provenance' | 'history'>('overview')
const cveIds = computed(() => {
  if (!item.value) return []
  const structured = item.value.attributes?.vulnerability
  const fromStructured = structured && typeof structured === 'object' && !Array.isArray(structured)
    ? (structured as Record<string, unknown>).cve_id : null
  const ids = [...(typeof fromStructured === 'string' ? [fromStructured] : []),
    ...(item.value.title.match(/CVE-[0-9]{4}-[0-9]{4,}/g) ?? [])]
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
  if (!Number.isSafeInteger(props.itemId) || props.itemId <= 0) {
    error.value = '記録IDが正しくありません。'
    loading.value = false
    return
  }
  loading.value = true
  try {
    const [detail, history] = await Promise.all([
      api.item(props.itemId, controller.signal),
      api.versions(props.itemId, controller.signal),
    ])
    if (epoch !== current || controller.signal.aborted) return
    item.value = detail
    versions.value = history.slice(0, 20)
  } catch (cause) {
    if (!controller.signal.aborted && epoch === current)
      error.value = cause instanceof Error ? cause.message : '記録を取得できませんでした。'
  } finally {
    if (epoch === current) loading.value = false
  }
}
watch(() => props.itemId, () => { tab.value = 'overview'; void load() }, { immediate: true })
onBeforeUnmount(() => controller?.abort())
</script>

<template>
  <article class="evidence-dossier">
    <div v-if="loading" class="evidence-loading" role="status" aria-label="記録を取得中">
      <q-skeleton type="text" width="32%" /><q-skeleton type="text" height="58px" />
      <q-skeleton type="text" width="70%" /><q-skeleton type="rect" height="170px" />
    </div>
    <div v-else-if="error" class="atlas-empty atlas-error evidence-error" role="alert">
      <span class="atlas-empty-code">RECORD / UNAVAILABLE</span><h2>この記録を取得できません</h2>
      <p>{{ error }}</p><q-btn outline no-caps label="再試行" @click="load" />
    </div>
    <template v-else-if="item">
      <header class="evidence-dossier-header">
        <div class="evidence-dossier-kicker">
          <span>{{ kindLabel(item.kind) }}</span><span class="evidence-state" :data-state="item.state">{{ stateLabel[item.state] }}</span>
          <span>RECORD {{ item.id }}</span>
        </div>
        <h1 class="evidence-dossier-title">{{ item.title }}</h1>
        <p class="evidence-dossier-publisher">{{ item.organization || item.source }} <span aria-hidden="true">/</span> {{ item.source }}</p>
        <div class="evidence-dossier-actions">
          <a class="evidence-publisher-link" :href="safeExternalUrl(item.url)" target="_blank"
            rel="noopener noreferrer" :aria-disabled="!safeExternalUrl(item.url)">
            発信元のページを開く <q-icon name="north_east" size="15px" aria-hidden="true" />
          </a>
          <span class="evidence-action-note">外部リンク · 新しいタブで開く</span>
        </div>
      </header>

      <dl class="evidence-time-register">
        <div><dt>発行日時</dt><dd><time v-if="item.published_at" :datetime="item.published_at">{{ dateLabel(item.published_at) }}</time><span v-else>発行日時なし</span></dd></div>
        <div><dt>初回観測</dt><dd><time :datetime="item.first_seen_at">{{ dateLabel(item.first_seen_at) }}</time></dd></div>
        <div><dt>最終観測</dt><dd><time :datetime="item.last_seen_at">{{ dateLabel(item.last_seen_at) }}</time></dd></div>
        <div><dt>記録版</dt><dd>v{{ item.current_version }}</dd></div>
      </dl>

      <div v-if="cveIds.length" class="evidence-cve-links">
        <div><span class="evidence-section-label">VULNERABILITY REFERENCE</span><h2>脆弱性情報との照合</h2></div>
        <div>
          <router-link v-for="cve in cveIds" :key="cve" :to="{ path: '/cves/' + cve, query: { returnTo: route.fullPath } }">
            {{ cve }} <span aria-hidden="true">↗</span>
          </router-link>
          <p>識別子への言及とKEV掲載は別の情報です。CISAのカタログ状態を個別に確認してください。</p>
        </div>
      </div>

      <nav class="evidence-tabs" aria-label="記録の閲覧項目">
        <button v-for="entry in [{ id: 'overview', label: '記録の概要' }, { id: 'provenance', label: '属性と出典' }, { id: 'history', label: '観測履歴' }]" :key="entry.id"
          type="button" :aria-current="tab === entry.id ? 'page' : undefined" @click="tab = entry.id as 'overview' | 'provenance' | 'history'">{{ entry.label }}</button>
      </nav>
      <section v-if="tab === 'overview'" class="evidence-section" aria-labelledby="evidence-overview-heading">
        <div class="evidence-section-heading"><span class="evidence-section-label">01 / CURRENT RECORD</span><h2 id="evidence-overview-heading">観測された記録</h2></div>
        <dl class="evidence-fact-list">
          <div><dt>情報源</dt><dd>{{ item.source }}</dd></div>
          <div><dt>記録種別</dt><dd>{{ kindLabel(item.kind) }}</dd></div>
          <div><dt>取得状態</dt><dd><span class="evidence-state" :data-state="item.state">{{ stateLabel[item.state] }}</span></dd></div>
          <div><dt>現在版</dt><dd>v{{ item.current_version }} · 初回取得からの観測履歴を保存</dd></div>
        </dl>
      </section>
      <section v-else-if="tab === 'provenance'" class="evidence-section" aria-labelledby="evidence-provenance-heading">
        <div class="evidence-section-heading"><span class="evidence-section-label">02 / ATTRIBUTES & PROVENANCE</span><h2 id="evidence-provenance-heading">属性と来歴</h2></div>
        <div v-if="Object.keys(item.attributes).length" class="evidence-register-group">
          <h3>正規化された属性</h3>
          <dl class="evidence-fact-list">
            <div v-for="[key, value] in Object.entries(item.attributes)" :key="key"><dt>{{ key }}</dt><dd>{{ safeValue(value) }}</dd></div>
          </dl>
        </div>
        <div class="evidence-register-group">
          <h3>出典メタデータ</h3>
          <dl v-if="Object.keys(item.provenance).length" class="evidence-fact-list">
            <div v-for="[key, value] in Object.entries(item.provenance)" :key="key"><dt>{{ key }}</dt><dd>{{ safeValue(value) }}</dd></div>
          </dl>
          <p v-else class="evidence-muted">保存された出典メタデータはありません。</p>
        </div>
      </section>
      <section v-else class="evidence-section" aria-labelledby="evidence-history-heading">
        <div class="evidence-section-heading"><span class="evidence-section-label">03 / IMMUTABLE OBSERVATIONS</span><h2 id="evidence-history-heading">観測履歴</h2></div>
        <p class="evidence-history-note">各版はその観測時点の記録です。過去の版は上書きされません。</p>
        <ol v-if="versions.length" class="evidence-version-list">
          <li v-for="version in versions" :key="version.version">
            <span class="evidence-version-mark" aria-hidden="true"></span>
            <div><strong>v{{ version.version }}</strong><time :datetime="version.observed_at">{{ dateLabel(version.observed_at) }}</time>
              <span class="evidence-version-hash">SHA-256 · {{ version.sha256 }}</span></div>
          </li>
        </ol>
        <p v-else class="evidence-muted">観測履歴はありません。</p>
      </section>
    </template>
  </article>
</template>
