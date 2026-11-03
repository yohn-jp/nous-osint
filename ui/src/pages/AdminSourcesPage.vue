<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, type ManagedSource, type CatalogEntry } from '../lib/api'
import { dateLabel, kindLabel } from '../lib/presentation'

const tab = ref<'official' | 'custom'>('official')
const catalog = ref<CatalogEntry[]>([])
const installed = ref<ManagedSource[]>([])
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
const officialRows = computed(() => catalog.value.filter(row =>
  row.config.id.includes(query.value.toLowerCase()) ||
  (row.config.organization ?? '').toLowerCase().includes(query.value.toLowerCase())
))
const customRows = computed(() => installed.value.filter(row => row.origin === 'custom' &&
  (row.id.includes(query.value.toLowerCase()) ||
  (row.config.organization ?? '').toLowerCase().includes(query.value.toLowerCase()))))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [c, s] = await Promise.all([api.adminCatalog(), api.adminSources()])
    catalog.value = c
    installed.value = s
  } catch (e) { error.value = e instanceof Error ? e.message : '管理情報を取得できません。' }
  finally { loading.value = false }
}
void load()

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
  <q-page class="nous-page">
    <div class="eyebrow q-mb-sm">OPERATIONS / SOURCE MANAGEMENT</div>
    <div class="row items-start justify-between q-gutter-md">
      <div>
        <h1 class="page-title q-ma-none">情報ソースを管理する。</h1>
        <p class="page-subtitle">公式カタログと独自ソース。設定はこのインスタンスのDBに保存されます。</p>
      </div>
      <q-btn color="primary" unelevated icon="add" label="独自ソースを追加" to="/admin/sources/new" />
    </div>
    <div class="admin-stats q-my-lg">
      <div class="admin-stat"><span>公式カタログ</span><strong>{{ catalog.length }}</strong></div>
      <div class="admin-stat"><span>独自ソース</span><strong>{{ installed.filter(s => s.origin === 'custom').length }}</strong></div>
      <div class="admin-stat"><span>収集中</span><strong>{{ installed.filter(s => s.enabled).length }}</strong></div>
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
      <template v-else-if="tab === 'official'">
        <p class="admin-hint">公式定義の配布元はGitです。ここで有効化・停止・収集予算を変更してもGitの更新で上書きされません。新規追加分は初期状態で停止しています。</p>
        <div v-if="!officialRows.length" class="empty-state">一致する公式ソースはありません。</div>
        <div v-for="entry in officialRows" :key="entry.config.id" class="admin-source">
          <div class="admin-source-main">
            <div class="row items-center q-gutter-sm">
              <strong>{{ entry.config.organization || entry.config.id }}</strong>
              <q-badge outline color="grey-7" label="公式" />
              <q-badge :color="runtimeRow(entry)?.enabled ? 'positive' : 'grey-6'" :label="runtimeRow(entry)?.enabled ? '収集中' : '停止'" />
            </div>
            <div class="admin-source-id">{{ entry.config.id }} · {{ kindLabel(entry.config.item_kind) }} · {{ entry.config.kind.toUpperCase() }}</div>
            <div class="admin-source-detail">{{ entry.config.url }}</div>
            <div v-if="runtimeRow(entry)?.last_error" class="text-negative text-caption">最終エラー: {{ runtimeRow(entry)?.last_error }}</div>
            <div class="admin-source-id">最終成功: {{ dateLabel(runtimeRow(entry)?.last_success_at ?? null) }}</div>
          </div>
          <div class="admin-source-actions">
            <q-btn dense flat color="primary" icon="science" label="接続検証" :loading="busy === entry.config.id" @click="probe(entry.config.id)" />
            <q-btn v-if="runtimeRow(entry)" dense flat icon="tune" color="primary" label="設定" @click="openSettings(runtimeRow(entry)!)" />
            <q-btn dense unelevated :color="runtimeRow(entry)?.enabled ? 'grey-7' : 'primary'" :disable="!runtimeRow(entry)" :loading="busy === entry.config.id" :label="runtimeRow(entry)?.enabled ? '停止' : '有効化'" @click="toggle(entry.config.id, !runtimeRow(entry)?.enabled)" />
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
              <q-badge :color="entry.enabled ? 'positive' : 'grey-6'" :label="entry.enabled ? '収集中' : '停止'" />
            </div>
            <div class="admin-source-id">{{ entry.id }} · {{ kindLabel(entry.config.item_kind) }} · {{ entry.config.kind.toUpperCase() }}</div>
            <div class="admin-source-detail">{{ entry.config.url }}</div>
            <div v-if="entry.last_error" class="text-negative text-caption">最終エラー: {{ entry.last_error }}</div>
          </div>
          <div class="admin-source-actions">
            <q-btn dense flat color="primary" icon="science" label="接続検証" :loading="busy === entry.id" @click="probe(entry.id)" />
            <q-btn dense flat icon="edit" color="primary" label="編集" :to="'/admin/sources/' + entry.id + '/edit'" />
            <q-btn dense flat icon="tune" color="primary" label="収集予算" @click="openSettings(entry)" />
            <q-btn dense unelevated :color="entry.enabled ? 'grey-7' : 'primary'" :loading="busy === entry.id" :label="entry.enabled ? '停止' : '有効化'" @click="toggle(entry.id, !entry.enabled)" />
          </div>
        </div>
      </template>
    </section>
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
