<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, type ManagedSource, type CatalogEntry } from '../lib/api'
import { dateLabel, kindLabel } from '../lib/presentation'

const tab = ref<'official' | 'custom'>('official')
const catalog = ref<CatalogEntry[] | null>(null)
const installed = ref<ManagedSource[] | null>(null)
const loading = ref(true)
const busy = ref('')
const error = ref('')
const feedback = ref('')
const query = ref('')
const settings = ref<ManagedSource | null>(null)
const interval = ref(360)
const hourly = ref(4)
const concurrency = ref(1)
const probeResult = ref<{ source: string; entries: number; sample: { title: string; url: string }[] } | null>(null)
const pendingToggle = ref<{ id: string; enabled: boolean } | null>(null)
const officialRows = computed(() => (catalog.value ?? []).filter(row =>
  row.config.id.includes(query.value.toLowerCase()) ||
  (row.config.organization ?? '').toLowerCase().includes(query.value.toLowerCase())
))
const customRows = computed(() => (installed.value ?? []).filter(row => row.origin === 'custom' &&
  (row.id.includes(query.value.toLowerCase()) ||
  (row.config.organization ?? '').toLowerCase().includes(query.value.toLowerCase()))))

async function load() {
  loading.value = true
  error.value = ''
  catalog.value = null
  installed.value = null
  try {
    const [c, s] = await Promise.all([api.adminCatalog(), api.adminSources()])
    catalog.value = c
    installed.value = s
  } catch (e) { error.value = e instanceof Error ? e.message : '管理情報を取得できません。' }
  finally { loading.value = false }
}
void load()

function requestToggle(id: string, enabled: boolean) {
  if (!busy.value) pendingToggle.value = { id, enabled }
}
async function confirmToggle() {
  const change = pendingToggle.value
  pendingToggle.value = null
  if (change) await toggle(change.id, change.enabled)
}
async function toggle(id: string, value: boolean) {
  busy.value = id
  feedback.value = ''
  error.value = ''
  try {
    await api.adminSettings(id, { enabled: value })
    await load()
    feedback.value = id + (value ? ' を有効化しました。' : ' を停止しました。')
  } catch (e) { error.value = e instanceof Error ? e.message : '変更できませんでした。' }
  finally { busy.value = '' }
}
function openSettings(entry: ManagedSource) {
  settings.value = entry
  interval.value = entry.config.interval_minutes
  hourly.value = entry.config.max_requests_per_hour
  concurrency.value = entry.config.max_concurrency
}
async function saveSettings() {
  if (!settings.value) return
  const id = settings.value.id
  busy.value = id
  feedback.value = ''
  try {
    await api.adminSettings(id, {
      interval_minutes: interval.value,
      max_requests_per_hour: hourly.value,
      max_concurrency: concurrency.value,
    })
    settings.value = null
    await load()
    feedback.value = id + ' の収集予算を更新しました。'
  } catch (e) { error.value = e instanceof Error ? e.message : '設定を保存できませんでした。' }
  finally { busy.value = '' }
}
async function probe(id: string) {
  busy.value = id
  probeResult.value = null
  feedback.value = ''
  error.value = ''
  try {
    probeResult.value = await api.adminProbe(id)
    feedback.value = id + ' の接続検証に成功しました。収集の有効化は別途行ってください。'
  } catch (e) { error.value = e instanceof Error ? e.message : '接続検証に失敗しました。' }
  finally { busy.value = '' }
}
const runtimeRow = (entry: CatalogEntry) => entry.runtime
</script>

<template>
  <q-page class="nous-page source-admin-page">
    <div class="row items-start justify-between q-gutter-md">
      <div>
        <h1 class="page-title q-ma-none">情報源管理</h1>
        <p class="page-subtitle">公式カタログと独自ソース。設定はこのインスタンスのDBに保存されます。</p>
      </div>
      <q-btn color="primary" unelevated icon="add" label="独自ソースを追加" to="/admin/sources/new" />
    </div>
    <div class="source-overview q-my-lg" role="status" aria-live="polite">
      <template v-if="loading">収集状態を読み込んでいます</template>
      <template v-else-if="catalog !== null && installed !== null">
        <strong>{{ installed.filter(s => s.enabled).length }}件が有効</strong>
        <span>{{ installed.filter(s => !s.enabled).length }}件が停止中</span>
        <span>公式定義 {{ catalog.length }}件</span>
        <span>独自ソース {{ installed.filter(s => s.origin === 'custom').length }}件</span>
      </template>
      <template v-else>収集状態を取得できません</template>
    </div>
    <q-banner v-if="error" class="bg-red-1 text-negative q-mb-md" role="alert">{{ error }} <q-btn flat dense label="再取得" @click="load" /></q-banner>
    <q-banner v-if="feedback" class="bg-green-1 text-green-9 q-mb-md" aria-live="polite">{{ feedback }}</q-banner>
    <section class="content-panel">
      <div class="admin-toolbar">
        <q-tabs v-model="tab" dense no-caps active-color="primary" indicator-color="primary" align="left">
          <q-tab name="official" label="公式カタログ" />
          <q-tab name="custom" label="カスタム" />
        </q-tabs>
        <div class="row items-center q-gutter-sm">
          <q-input v-model.trim="query" clearable dense outlined placeholder="名前・提供元で検索" style="width: min(240px, 100%)" />
          <q-btn flat dense round icon="refresh" color="primary" aria-label="更新" @click="load" />
        </div>
      </div>
      <q-separator />
      <div v-if="loading" class="q-pa-lg"><q-skeleton v-for="n in 4" :key="n" type="rect" height="78px" class="q-mb-md" /></div>
      <div v-else-if="catalog === null || installed === null" class="q-pa-lg text-grey-7" role="status">
        管理データを取得できないため、一覧を表示できません。
      </div>
      <template v-else-if="tab === 'official'">
        <p class="admin-hint">公式定義の配布元はGitです。ここで有効化・停止・収集予算を変更してもGitの更新で上書きされません。新規追加分は初期状態で停止しています。</p>
        <div v-if="!officialRows.length" class="empty-state">一致する公式ソースはありません。</div>
        <div v-for="entry in officialRows" :key="entry.config.id" class="admin-source">
          <div class="admin-source-main">
            <div class="row items-center q-gutter-sm">
              <strong>{{ entry.config.organization || entry.config.id }}</strong>
              <q-badge outline color="grey-7" label="公式" />
              <q-badge :color="runtimeRow(entry)?.enabled ? 'positive' : 'grey-6'" :label="!runtimeRow(entry) ? '未導入' : runtimeRow(entry)?.enabled ? '有効' : '停止'" />
            </div>
            <div class="admin-source-id">{{ entry.config.id }} · {{ kindLabel(entry.config.item_kind) }} · {{ entry.config.kind.toUpperCase() }}</div>
            <div class="admin-source-id">権利表示: {{ entry.config.policy.license_id || 'NOASSERTION' }} · {{ entry.config.policy.attribution || '提供元未記録' }}</div>
            <a v-if="entry.config.policy.license_url || entry.config.policy.terms_url" class="text-caption" :href="entry.config.policy.license_url || entry.config.policy.terms_url || undefined" target="_blank" rel="noopener noreferrer">提供元の利用条件・ライセンスを確認</a>
            <div class="admin-source-detail">{{ entry.config.url }}</div>
            <div v-if="runtimeRow(entry)?.last_error" class="text-negative text-caption">最終エラー: {{ runtimeRow(entry)?.last_error }}</div>
            <div class="admin-source-id">取得間隔: {{ runtimeRow(entry)?.config.interval_minutes ?? entry.config.interval_minutes }}分 · 最終成功: {{ dateLabel(runtimeRow(entry)?.last_success_at ?? null) }}</div>
          </div>
          <div class="admin-source-actions">
            <q-btn dense flat color="primary" icon="science" label="接続検証" :disable="!!busy && busy !== entry.config.id" :loading="busy === entry.config.id" @click="probe(entry.config.id)" />
            <q-btn v-if="runtimeRow(entry)" dense flat icon="tune" color="primary" label="設定" :disable="!!busy" @click="openSettings(runtimeRow(entry)!)" />
            <q-btn dense outline :color="runtimeRow(entry)?.enabled ? 'grey-7' : 'primary'" :disable="!runtimeRow(entry) || !!busy" :loading="busy === entry.config.id" :label="runtimeRow(entry)?.enabled ? '収集を停止' : '有効化'" @click="requestToggle(entry.config.id, !runtimeRow(entry)?.enabled)" />
          </div>
        </div>
      </template>
      <template v-else>
        <p class="admin-hint">独自ソースはこのインスタンスにだけ保存され、Gitや他のNous環境には影響しません。</p>
        <div v-if="!customRows.length" class="empty-state">カスタムソースがありません。右上から追加できます。</div>
        <div v-for="entry in customRows" :key="entry.id" class="admin-source">
          <div class="admin-source-main">
            <div class="row items-center q-gutter-sm"><strong>{{ entry.config.organization || entry.id }}</strong>
              <q-badge outline color="grey-7" label="独自" />
              <q-badge :color="entry.enabled ? 'positive' : 'grey-6'" :label="entry.enabled ? '有効' : '停止'" />
            </div>
            <div class="admin-source-id">{{ entry.id }} · {{ kindLabel(entry.config.item_kind) }} · {{ entry.config.kind.toUpperCase() }}</div>
            <div class="admin-source-detail">{{ entry.config.url }}</div>
            <div class="admin-source-id">取得間隔: {{ entry.config.interval_minutes }}分 · 最終成功: {{ dateLabel(entry.last_success_at) }}</div>
            <div v-if="entry.last_error" class="text-negative text-caption">最終エラー: {{ entry.last_error }}</div>
          </div>
          <div class="admin-source-actions">
            <q-btn dense flat color="primary" icon="science" label="接続検証" :disable="!!busy && busy !== entry.id" :loading="busy === entry.id" @click="probe(entry.id)" />
            <q-btn dense flat icon="edit" color="primary" label="編集" :disable="!!busy" :to="'/admin/sources/' + entry.id + '/edit'" />
            <q-btn dense flat icon="tune" color="primary" label="収集予算" :disable="!!busy" @click="openSettings(entry)" />
            <q-btn dense outline :color="entry.enabled ? 'grey-7' : 'primary'" :disable="!!busy" :loading="busy === entry.id" :label="entry.enabled ? '収集を停止' : '有効化'" @click="requestToggle(entry.id, !entry.enabled)" />
          </div>
        </div>
      </template>
    </section>
    <q-dialog :model-value="!!pendingToggle" @update:model-value="value => { if (!value) pendingToggle = null }">
      <q-card class="admin-confirm-card">
        <q-card-section>
          <div class="text-h6">{{ pendingToggle?.enabled ? '収集を有効にしますか？' : '収集を停止しますか？' }}</div>
          <div class="admin-source-detail q-mt-sm">{{ pendingToggle?.id }}</div>
          <p class="q-mt-md q-mb-none">
            {{ pendingToggle?.enabled
              ? 'この情報源を定期収集の対象に追加します。取得タイミングは設定された収集間隔に従います。'
              : 'この情報源を以降の定期収集の対象から外します。保存済みの観測履歴は削除されません。' }}
          </p>
        </q-card-section>
        <q-card-actions align="right" class="q-pa-md">
          <q-btn flat label="キャンセル" no-caps v-close-popup />
          <q-btn unelevated color="primary" :label="pendingToggle?.enabled ? '有効化する' : '停止する'" no-caps @click="confirmToggle" />
        </q-card-actions>
      </q-card>
    </q-dialog>
    <q-dialog :model-value="!!settings" @update:model-value="value => { if (!value) settings = null }" persistent>
      <q-card style="width: min(460px, 94vw)">
        <q-card-section><div class="text-h6">収集予算</div><div class="text-caption text-grey-7">{{ settings?.id }}</div></q-card-section>
        <q-card-section class="q-gutter-md">
          <q-input v-model.number="interval" type="number" outlined dense label="取得間隔（分・15以上）" />
          <q-input v-model.number="hourly" type="number" outlined dense label="最大リクエスト数／時（1–60）" />
          <q-input v-model.number="concurrency" type="number" outlined dense label="同時取得数（1–4）" />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="キャンセル" v-close-popup />
          <q-btn unelevated color="primary" label="保存" :disable="!Number.isInteger(interval) || interval < 15 || !Number.isInteger(hourly) || hourly < 1 || hourly > 60 || !Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4" :loading="!!busy" @click="saveSettings" />
        </q-card-actions>
      </q-card>
    </q-dialog>
    <q-dialog :model-value="!!probeResult" @update:model-value="value => { if (!value) probeResult = null }">
      <q-card style="width: min(560px, 94vw)">
        <q-card-section><div class="text-h6">接続検証結果</div>
          <div class="text-caption">{{ probeResult?.source }} · {{ probeResult?.entries }} 件抽出</div>
        </q-card-section>
        <q-card-section v-if="probeResult">
          <div v-for="item in probeResult.sample" :key="item.url" class="q-mb-md">
            <div class="text-weight-medium">{{ item.title }}</div>
            <div class="text-caption admin-source-detail">{{ item.url }}</div>
          </div>
          <div class="text-caption text-grey-7">取得と抽出の検証です。利用条件の承認や収集開始を意味しません。</div>
        </q-card-section>
        <q-card-actions align="right"><q-btn flat label="閉じる" v-close-popup /></q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>
