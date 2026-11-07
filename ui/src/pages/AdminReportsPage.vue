<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { api, type ReportRun, type ReportRunListItem, type ReportSchedule, type ReportTemplate, type ReportTemplateId } from '../lib/api'

const templates = ref<ReportTemplate[]>([])
const runs = ref<ReportRunListItem[]>([])
const schedules = ref<ReportSchedule[]>([])
const selectedRun = ref<ReportRun | null>(null)
const selectedTemplate = ref<ReportTemplateId>('security-daily')
const loading = ref(true)
const dataReady = ref(false)
const refreshing = ref(false)
const loadingOlder = ref(false)
const nextRunCursor = ref<string | null>(null)
const nextScheduleCursor = ref<string | null>(null)
const loadingOlderSchedules = ref(false)
const busy = ref('')
const error = ref('')
const feedback = ref('')
const lastSyncedAt = ref<string | null>(null)
const runFilter = ref<'all' | 'active' | 'failed' | 'published'>('all')
const runFilterOptions = [
  { value: 'all', label: 'すべて' },
  { value: 'active', label: '処理中' },
  { value: 'failed', label: '失敗' },
  { value: 'published', label: '公開済み' },
] as const
let pollTimer: ReturnType<typeof setInterval> | undefined

function tokyoDate() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Tokyo' }).format(new Date())
}
function dateInTimezone(timezone: string) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: timezone }).format(new Date())
}

const targetDate = ref(tokyoDate())
const targetTimezone = ref('Asia/Tokyo')
const reportCategory = ref<'security' | 'advisory' | 'vulnerability' | null>(null)
const cveId = ref('')
const periodDays = ref(30)
const availableSources = ref<import('../lib/api').Source[]>([])
const sourceCategoryOptions = [
  { label: '脆弱性データベース', value: 'vulnerability' },
  { label: '公式アドバイザリ', value: 'advisory' },
  { label: '脅威・攻撃調査', value: 'threat_research' },
  { label: 'セキュリティ動向', value: 'security_news' },
  { label: '企業・業界動向', value: 'industry' },
  { label: '求人情報', value: 'careers' },
]
const selectedCategories = ref<string[]>([])
const selectedSourceIds = ref<string[]>([])
const scheduleCategories = ref<string[]>([])
const scheduleSourceIds = ref<string[]>([])
const sourceOptions = computed(() => availableSources.value
  .filter(s => s.enabled && (!selectedCategories.value.length || selectedCategories.value.includes(s.category)))
  .map(s => ({ value: s.id, label: s.id })))
const scheduleSourceOptions = computed(() => availableSources.value
  .filter(s => s.enabled && (!scheduleCategories.value.length || scheduleCategories.value.includes(s.category)))
  .map(s => ({ value: s.id, label: s.id })))
const scopeParameters = (categories: string[], ids: string[]) => ({
  ...(categories.length ? { source_categories: [...categories] } : {}),
  ...(ids.length ? { source_ids: [...ids] } : {}),
})

const scheduleTimezone = ref('Asia/Tokyo')
const scheduleCadence = ref<'daily' | 'weekly'>('daily')
const scheduleTime = ref('08:00')
const scheduleCategory = ref<'security' | 'advisory' | 'vulnerability' | null>(null)

const sortedRuns = computed(() => [...runs.value].sort((a, b) =>
  b.created_at.localeCompare(a.created_at)))
const visibleRuns = computed(() => sortedRuns.value.filter(run => {
  if (runFilter.value === 'active') return ['queued', 'leased', 'running', 'validating', 'publishing'].includes(run.state)
  if (runFilter.value === 'failed') return run.state === 'failed'
  if (runFilter.value === 'published') return run.state === 'published'
  return true
}))
const activeCount = computed(() => runs.value.filter(run =>
  ['queued', 'leased', 'running', 'validating', 'publishing'].includes(run.state)).length)
const publishedCount = computed(() => runs.value.filter(run => run.state === 'published').length)
const canSubmitCve = computed(() => /^CVE-[0-9]{4}-[0-9]{4,}$/.test(cveId.value.trim()) &&
  cveId.value.trim().length <= 64 && Number.isInteger(periodDays.value) &&
  periodDays.value >= 1 && periodDays.value <= 90)

const templateTitle = (id: ReportTemplateId) =>
  templates.value.find(template => template.id === id)?.title ?? id
const stateLabel = (state: ReportRunListItem['state']) => ({
  queued: '待機中', leased: '割当済み', running: '生成中', validating: '検査中',
  publishing: '公開処理中', published: '公開済み', skipped: '対象外',
  failed: '失敗', cancelled: '取消済み',
}[state] ?? state)
const stageLabel = (stage: string) => ({
  queued: '待機中', claimed: 'ワーカー割当', evidence: '根拠スナップショット',
  plan: '企画（旧履歴）', fact_check: '事実検証（旧履歴）', draft: '執筆（旧履歴）',
  codex_preflight: '実行環境確認', claims: '企画・主張生成', claim_review: '独立レビュー',
  claim_repair: '主張修正', claim_rereview: '再レビュー', assembly: '記事組立',
  article_validation: '記事検証', article: '完成記事',
  article_validated: '決定論的検査', publishing: '静的公開', published: '公開済み',
  retry_wait: '再試行待ち', failed: '失敗', skipped: '対象外',
}[stage] ?? stage)
const eventLabel = (eventType: string) => ({
  stage_started: '工程開始', stage_completed: '工程完了', stage_failed: '工程失敗',
  codex_stage_started: 'Codex開始', codex_stage_completed: 'Codex完了',
  codex_stage_failed: 'Codex失敗', artifact_persisted: '成果物保存',
  stage_succeeded: '工程成果を保存', run_failed: '実行失敗',
  retry_scheduled: '再試行予約', run_skipped: '対象外として終了',
  report_published: '公開完了',
}[eventType] ?? eventType)
const durationLabel = (value: number | null) => {
  if (value === null || !Number.isFinite(value) || value < 0) return '—'
  return value >= 1000 ? `${(value / 1000).toFixed(1)}秒` : `${value}ミリ秒`
}
const categoryLabel = (value: string | null) => ({
  security: '全カテゴリ', advisory: 'アドバイザリ', vulnerability: '脆弱性',
}[value ?? 'security'] ?? '全カテゴリ')
const dateLabel = (value: string) => {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat('ja-JP', {
    dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Tokyo',
  }).format(date)
}
const safeReportUrl = (value: string | null) => value &&
  /^\/reports\/(?:security|cve)\/[a-z0-9-]{1,128}\/$/.test(value) ? value : null

async function loadData(initial = false) {
  if (loading.value && dataReady.value === false && !initial) return
  if (refreshing.value && !initial) return
  if (initial) loading.value = true
  else refreshing.value = true
  error.value = ''
  try {
    const [templateRows, runPage, schedulePage, sourceRows] = await Promise.all([
      api.adminReportTemplates(), api.adminReportRuns({ limit: 50 }),
      api.adminReportSchedules({ limit: 100 }), api.sources(),
    ])
    availableSources.value = sourceRows
    templates.value = templateRows
    dataReady.value = true
    lastSyncedAt.value = new Date().toISOString()
    const newestIds = new Set(runPage.runs.map(run => run.run_id))
    runs.value = [...runPage.runs, ...runs.value.filter(run => !newestIds.has(run.run_id))]
    nextRunCursor.value = runPage.next_cursor
    const scheduleIds = new Set(schedulePage.schedules.map(schedule => schedule.id))
    const previouslyLoaded = schedules.value.length
    const knownBeforeRefresh = new Set(schedules.value.map(schedule => schedule.id))
    const pageTail = schedulePage.schedules[schedulePage.schedules.length - 1]
    schedules.value = [
      ...schedulePage.schedules,
      ...schedules.value.filter(schedule => !scheduleIds.has(schedule.id)),
    ].sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id))
    // Keep the oldest cursor when pages are contiguous. If >100 new schedules
    // appeared between refreshes, restart pagination at the new page boundary
    // so no middle page can become permanently unreachable.
    if (previouslyLoaded <= 100 || (pageTail && !knownBeforeRefresh.has(pageTail.id))) {
      nextScheduleCursor.value = schedulePage.next_cursor
    }
    if (selectedRun.value) {
      selectedRun.value = await api.adminReportRun(selectedRun.value.run_id)
    }
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'レポート管理情報を取得できません。'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

async function loadOlderRuns() {
  if (!nextRunCursor.value || loadingOlder.value) return
  loadingOlder.value = true
  error.value = ''
  try {
    const page = await api.adminReportRuns({ limit: 50, cursor: nextRunCursor.value })
    const existing = new Set(runs.value.map(run => run.run_id))
    runs.value = [...runs.value, ...page.runs.filter(run => !existing.has(run.run_id))]
    nextRunCursor.value = page.next_cursor
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '古い実行履歴を取得できません。'
  } finally { loadingOlder.value = false }
}

async function loadOlderSchedules() {
  if (!nextScheduleCursor.value || loadingOlderSchedules.value) return
  loadingOlderSchedules.value = true
  error.value = ''
  try {
    const page = await api.adminReportSchedules({ limit: 100, cursor: nextScheduleCursor.value })
    const existing = new Set(schedules.value.map(schedule => schedule.id))
    schedules.value = [
      ...schedules.value,
      ...page.schedules.filter(schedule => !existing.has(schedule.id)),
    ].sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id))
    nextScheduleCursor.value = page.next_cursor
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '古いスケジュールを取得できません。'
  } finally { loadingOlderSchedules.value = false }
}

async function enqueueRun() {
  error.value = ''
  feedback.value = ''
  busy.value = 'run'
  try {
    const request = selectedTemplate.value === 'security-daily'
      ? {
          template_id: selectedTemplate.value,
          parameters: {
            target_date: targetDate.value,
            timezone: targetTimezone.value,
            category: reportCategory.value,
            ...scopeParameters(selectedCategories.value, selectedSourceIds.value),
          },
          idempotency_key: crypto.randomUUID(),
        }
      : {
          template_id: selectedTemplate.value,
          parameters: { cve_id: cveId.value.trim(), period_days: periodDays.value,
            ...scopeParameters(selectedCategories.value, selectedSourceIds.value) },
          idempotency_key: crypto.randomUUID(),
        }
    const result = await api.adminCreateReportRun(request)
    feedback.value = `実行を受け付けました（${result.run_id}）。状態をこの画面で確認できます。`
    await loadData()
    selectedRun.value = await api.adminReportRun(result.run_id)
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '実行を登録できませんでした。'
  } finally { busy.value = '' }
}

async function showRun(runId: string) {
  selectedRun.value = null
  busy.value = `detail:${runId}`
  error.value = ''
  try { selectedRun.value = await api.adminReportRun(runId) }
  catch (cause) { error.value = cause instanceof Error ? cause.message : '実行詳細を取得できません。' }
  finally { busy.value = '' }
}

async function createSchedule() {
  error.value = ''
  feedback.value = ''
  busy.value = 'schedule'
  try {
    await api.adminCreateReportSchedule({
      template_id: 'security-daily',
      parameters: { category: scheduleCategory.value,
        ...scopeParameters(scheduleCategories.value, scheduleSourceIds.value) },
      timezone: scheduleTimezone.value,
      cadence: scheduleCadence.value,
      local_time: scheduleTime.value,
    })
    feedback.value = 'スケジュールを保存しました。次回予定を一覧で確認してください。'
    await loadData()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'スケジュールを保存できませんでした。'
  } finally { busy.value = '' }
}

async function toggleSchedule(schedule: ReportSchedule) {
  busy.value = `schedule:${schedule.id}`
  error.value = ''
  feedback.value = ''
  try {
    await api.adminUpdateReportSchedule(schedule.id, { enabled: !schedule.enabled })
    feedback.value = schedule.enabled ? 'スケジュールを停止しました。' : 'スケジュールを有効にしました。'
    await loadData()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'スケジュールを変更できませんでした。'
  } finally { busy.value = '' }
}

onMounted(() => {
  void loadData(true)
  pollTimer = setInterval(() => { void loadData() }, 10000)
})
onBeforeUnmount(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<template>
  <q-page class="nous-page report-admin">
    <div class="row items-center justify-between q-gutter-sm">
      <div>
        <h1 class="page-title q-ma-none">レポート生成</h1>
        <p class="page-subtitle q-mb-none">検証済みテンプレートを実行し、生成状態と定期実行を管理します。</p>
      </div>
      <q-btn flat color="primary" icon="open_in_new" label="公開レポートを開く" href="/reports/" />
    </div>

    <q-banner v-if="error" class="bg-red-1 text-negative q-mt-md" role="alert">
      <div class="row items-center justify-between q-gutter-sm">
        <span>{{ error }}</span>
        <q-btn flat no-caps label="再取得" :loading="refreshing" @click="loadData(true)" />
      </div>
    </q-banner>
    <q-banner v-if="feedback" class="bg-green-1 text-positive q-mt-md" role="status">{{ feedback }}</q-banner>

    <div v-if="dataReady" class="report-stats q-mt-lg">
      <div class="admin-stat"><span>読み込み済みの実行</span><strong>{{ runs.length }}</strong></div>
      <div class="admin-stat"><span>処理中・待機中</span><strong>{{ activeCount }}</strong></div>
      <div class="admin-stat"><span>公開済み（読込範囲）</span><strong>{{ publishedCount }}</strong></div>
    </div>

    <section class="content-panel q-mt-lg" aria-labelledby="new-report-heading">
      <div class="section-heading">
        <div>
          <div class="eyebrow">RUN / AD HOC</div>
          <h2 id="new-report-heading" class="text-h6 q-mb-none q-mt-xs">随時実行</h2>
        </div>
        <q-spinner v-if="loading" color="primary" size="24px" aria-label="読み込み中" />
      </div>
      <div v-if="loading" class="empty-state" role="status">テンプレートを読み込んでいます。</div>
      <div v-else-if="!dataReady" class="empty-state" role="status">管理情報を取得できません。再取得してください。</div>
      <div v-else class="report-form-wrap">
        <div class="report-source-scope">
          <div class="report-source-scope-heading"><strong>根拠に利用する情報源</strong>
            <span>指定しなければテンプレートの既定対象を使用します。カテゴリと情報源の指定は絞り込み条件です。</span></div>
          <div class="row q-col-gutter-sm">
            <div class="col-12 col-md-6"><q-select v-model="selectedCategories" multiple use-chips dense outlined clearable
              emit-value map-options :options="sourceCategoryOptions" label="カテゴリを選択"
              @update:model-value="selectedSourceIds = selectedSourceIds.filter(id => sourceOptions.some(s => s.value === id))" /></div>
            <div class="col-12 col-md-6"><q-select v-model="selectedSourceIds" multiple use-chips dense outlined clearable
              emit-value map-options :options="sourceOptions" label="情報源を指定（任意）" /></div>
          </div>
          <p class="report-source-scope-note">有効な情報源 {{ sourceOptions.length }} 件。CVEに関するKEV判定はCISAの記録を独立して参照します。</p>
        </div>
        <q-tabs v-model="selectedTemplate" dense no-caps align="left" active-color="primary" indicator-color="primary" class="report-template-tabs">
          <q-tab name="security-daily" icon="shield" label="日次セキュリティ" />
          <q-tab name="cve-kev-deep-dive" icon="bug_report" label="CVE / KEV 詳細" />
        </q-tabs>
        <div class="report-form q-pt-lg">
          <p class="admin-hint q-mb-md">{{ templateTitle(selectedTemplate) }}。自由なプロンプトや任意URLは受け付けず、取得済みの情報源だけを参照します。</p>
          <q-form v-if="selectedTemplate === 'security-daily'" class="row q-col-gutter-md" @submit.prevent="enqueueRun">
            <div class="col-12 col-sm-4">
              <q-input v-model="targetDate" outlined dense type="date" stack-label label="対象日" :max="dateInTimezone(targetTimezone)" :rules="[v => !!v || '対象日を選択してください']" />
            </div>
            <div class="col-12 col-sm-4">
              <q-select v-model="targetTimezone" outlined dense emit-value map-options label="日付のタイムゾーン"
                :options="[{label:'日本標準時',value:'Asia/Tokyo'},{label:'協定世界時',value:'UTC'}]" />
            </div>
            <div class="col-12 col-sm-4">
              <q-select v-model="reportCategory" outlined dense emit-value map-options clearable label="対象カテゴリ（任意）"
                :options="[{label:'すべて',value:null},{label:'アドバイザリ',value:'advisory'},{label:'脆弱性',value:'vulnerability'}]" />
            </div>
            <div class="col-12 row justify-end">
              <q-btn color="primary" unelevated type="submit" icon="play_arrow" label="レポートを生成" :loading="busy === 'run'" />
            </div>
          </q-form>
          <q-form v-else class="row q-col-gutter-md" @submit.prevent="enqueueRun">
            <div class="col-12 col-md-7">
              <q-input :model-value="cveId" outlined dense autocapitalize="characters" label="正規化済み CVE ID" placeholder="CVE-2026-12345"
                @update:model-value="value => cveId = String(value ?? '').trim().toUpperCase()"
                :rules="[v => /^CVE-[0-9]{4}-[0-9]{4,}$/.test(v) && v.length <= 64 || 'CVE-YYYY-NNNN 形式で入力してください']" />
            </div>
            <div class="col-12 col-md-5">
              <q-input v-model.number="periodDays" outlined dense type="number" min="1" max="90" label="観測期間（日）"
                :rules="[v => Number.isInteger(v) && v >= 1 && v <= 90 || '1〜90日の範囲で指定してください']" />
            </div>
            <div class="col-12 row justify-end">
              <q-btn color="primary" unelevated type="submit" icon="play_arrow" label="CVE レポートを生成" :loading="busy === 'run'" :disable="!canSubmitCve" />
            </div>
          </q-form>
        </div>
      </div>
    </section>

    <section class="content-panel q-mt-lg" aria-labelledby="runs-heading">
      <div class="section-heading">
        <div>
          <div class="eyebrow">EXECUTION / HISTORY</div>
          <h2 id="runs-heading" class="text-h6 q-mb-none q-mt-xs">生成ジョブ</h2>
        </div>
        <div class="row items-center q-gutter-sm">
          <span v-if="lastSyncedAt" class="run-sync-time">最終確認 {{ dateLabel(lastSyncedAt) }}</span>
          <q-btn flat round dense icon="refresh" aria-label="実行履歴を更新" :loading="refreshing" @click="loadData()" />
        </div>
      </div>
      <div v-if="dataReady && runs.length" class="report-run-filters" role="group" aria-label="実行状態で絞り込む">
        <button v-for="filter in runFilterOptions" :key="filter.value" type="button" class="report-run-filter"
          :aria-pressed="runFilter === filter.value" :class="{ active: runFilter === filter.value }"
          @click="runFilter = filter.value">{{ filter.label }}</button>
        <span class="report-run-filter-count">{{ visibleRuns.length }} 件</span>
      </div>
      <div v-if="loading" class="empty-state" role="status">実行履歴を読み込んでいます。</div>
      <div v-else-if="!dataReady" class="empty-state" role="status">実行履歴を取得できません。</div>
      <div v-else-if="!sortedRuns.length" class="empty-state">実行履歴はありません。テンプレートを選んで実行できます。</div>
      <div v-else-if="!visibleRuns.length" class="workstation-message report-run-empty">この状態の実行履歴はありません。絞り込みを変更してください。</div>
      <div v-else class="run-grid">
        <div class="run-list" role="list" aria-label="レポート生成ジョブ">
          <button v-for="run in visibleRuns" :key="run.run_id" class="run-row" :class="{selected:selectedRun?.run_id===run.run_id}"
            type="button" role="listitem" @click="showRun(run.run_id)">
            <span class="run-row-main">
              <span class="run-title">{{ templateTitle(run.template_id) }}</span>
              <span class="run-meta">{{ dateLabel(run.created_at) }} · {{ run.trigger === 'scheduled' ? 'スケジュール' : '随時実行' }}</span>
              <span class="run-meta">工程: {{ stageLabel(run.stage) }} · 試行 {{ run.attempts }}</span>
            </span>
            <span class="run-state" :class="`state-${run.state}`">{{ stateLabel(run.state) }}</span>
          </button>
        </div>
        <aside v-if="selectedRun" class="run-detail" aria-live="polite">
          <div class="row items-start justify-between q-gutter-sm">
            <div>
              <div class="eyebrow">RUN DETAIL</div>
              <div class="text-subtitle1 text-weight-bold q-mt-xs">{{ templateTitle(selectedRun.template_id) }}</div>
            </div>
            <q-btn flat round dense icon="close" aria-label="詳細を閉じる" @click="selectedRun = null" />
          </div>
          <div class="detail-line"><span>状態</span><strong>{{ stateLabel(selectedRun.state) }} / {{ stageLabel(selectedRun.stage) }}</strong></div>
          <div class="detail-line"><span>実行ID</span><code>{{ selectedRun.run_id }}</code></div>
          <div class="detail-line"><span>開始</span><strong>{{ dateLabel(selectedRun.created_at) }}</strong></div>
          <div class="detail-line"><span>試行</span><strong>{{ selectedRun.attempts }}回</strong></div>
          <div v-if="selectedRun.error_code" class="detail-line text-negative"><span>失敗コード</span><code>{{ selectedRun.error_code }}</code></div>
          <div v-if="selectedRun.failed_stage" class="detail-line text-negative"><span>失敗工程</span><strong>{{ stageLabel(selectedRun.failed_stage) }}</strong></div>
          <div v-if="selectedRun.retry_at" class="detail-line"><span>再試行予定</span><strong>{{ dateLabel(selectedRun.retry_at) }}</strong></div>
          <div v-if="Object.keys(selectedRun.stages ?? {}).length" class="q-mt-md">
            <div class="text-caption text-weight-bold q-mb-xs">保存済みの工程</div>
            <div v-for="[name, status] in Object.entries(selectedRun.stages)" :key="name" class="stage-line">
              <span>{{ stageLabel(name) }}</span><span>{{ status }}</span>
            </div>
          </div>
          <div v-if="selectedRun.events?.length" class="q-mt-md">
            <div class="text-caption text-weight-bold q-mb-xs">工程イベント（最新100件）</div>
            <ol class="event-timeline" aria-label="工程イベント履歴">
              <li v-for="event in selectedRun.events" :key="`${event.attempt}:${event.seq}`" class="event-row"
                :class="{ 'event-failed': event.error_code }">
                <div class="event-heading">
                  <strong>{{ eventLabel(event.event_type) }} · {{ stageLabel(event.stage) }}</strong>
                  <span>{{ dateLabel(event.created_at) }}</span>
                </div>
                <div class="event-meta">
                  試行 {{ event.attempt }} · 所要 {{ durationLabel(event.elapsed_ms) }}
                  <template v-if="event.exit_status !== null"> · exit {{ event.exit_status }}</template>
                  <template v-if="event.retryable !== null"> · {{ event.retryable ? '再試行可能' : '再試行不可' }}</template>
                </div>
                <div v-if="event.error_code" class="event-code">{{ event.error_code }}</div>
                <div v-if="event.jsonl_last_event || event.cli_version" class="event-meta">
                  <template v-if="event.jsonl_last_event">JSONL: {{ event.jsonl_last_event }}</template>
                  <template v-if="event.cli_version"> · Codex CLI {{ event.cli_version }}</template>
                </div>
                <div v-if="event.stdout_bytes !== null || event.stderr_bytes !== null" class="event-meta">
                  ログ量: stdout {{ event.stdout_bytes ?? 0 }} B / stderr {{ event.stderr_bytes ?? 0 }} B
                </div>
                <div v-if="event.usage" class="event-meta">
                  使用量: {{ event.usage.input_tokens ?? 0 }} input / {{ event.usage.output_tokens ?? 0 }} output token
                </div>
                <div v-if="event.diagnostic_ref" class="event-meta">診断参照: <code>{{ event.diagnostic_ref }}</code></div>
                <div v-if="event.artifact_sha256" class="event-meta">成果物 SHA-256: <code>{{ event.artifact_sha256 }}</code></div>
              </li>
            </ol>
          </div>
          <div v-else class="admin-hint q-mt-md">工程イベントはまだありません。</div>
          <q-btn v-if="safeReportUrl(selectedRun.published_url)" class="q-mt-md full-width" color="primary" outline icon="article"
            label="公開記事を開く" :href="safeReportUrl(selectedRun.published_url) ?? undefined" />
        </aside>
        <aside v-else class="run-detail run-detail-empty">
          <div class="empty-state">ジョブを選ぶと工程と公開先を表示します。</div>
        </aside>
      </div>
      <div v-if="nextRunCursor" class="row justify-center q-pa-md">
        <q-btn flat color="primary" icon="expand_more" label="さらに読み込む" :loading="loadingOlder" @click="loadOlderRuns" />
      </div>
      <div class="admin-hint">最新50件から表示します。古い履歴は追加で読み込めます。状態は10秒ごとに取得します。処理状況はワーカーが最後に保存した状態です。</div>
    </section>

    <section class="content-panel q-mt-lg" aria-labelledby="schedule-heading">
      <div class="section-heading">
        <div>
          <div class="eyebrow">SCHEDULE</div>
          <h2 id="schedule-heading" class="text-h6 q-mb-none q-mt-xs">日次レポートのスケジュール</h2>
        </div>
      </div>
      <div class="admin-hint">スケジュールは `security-daily` テンプレートだけを登録できます。CVE 詳細は随時実行してください。</div>
      <div v-if="dataReady" class="report-source-scope report-schedule-scope">
        <strong>定期レポートの収集対象</strong>
        <p>新しい実行ごとに、このカテゴリと情報源を条件に根拠を収集します。</p>
        <div class="row q-col-gutter-sm">
          <div class="col-12 col-md-6"><q-select v-model="scheduleCategories" multiple use-chips dense outlined clearable
            emit-value map-options :options="sourceCategoryOptions" label="対象カテゴリ"
            @update:model-value="scheduleSourceIds = scheduleSourceIds.filter(id => scheduleSourceOptions.some(s => s.value === id))" /></div>
          <div class="col-12 col-md-6"><q-select v-model="scheduleSourceIds" multiple use-chips dense outlined clearable
            emit-value map-options :options="scheduleSourceOptions" label="対象情報源（任意）" /></div>
        </div>
      </div>
      <q-form v-if="dataReady" class="schedule-form row q-col-gutter-md" @submit.prevent="createSchedule">
        <div class="col-12 col-sm-6 col-lg-3">
          <q-select v-model="scheduleCadence" outlined dense emit-value map-options label="間隔"
            :options="[{label:'毎日',value:'daily'},{label:'毎週',value:'weekly'}]" />
        </div>
        <div class="col-12 col-sm-6 col-lg-3">
          <q-input v-model="scheduleTime" outlined dense type="time" stack-label label="実行時刻" />
        </div>
        <div class="col-12 col-sm-6 col-lg-3">
          <q-select v-model="scheduleTimezone" outlined dense emit-value map-options label="タイムゾーン"
            :options="[{label:'日本標準時',value:'Asia/Tokyo'},{label:'協定世界時',value:'UTC'}]" />
        </div>
        <div class="col-12 col-sm-6 col-lg-3">
          <q-select v-model="scheduleCategory" outlined dense emit-value map-options clearable label="対象カテゴリ（任意）"
            :options="[{label:'すべて',value:null},{label:'アドバイザリ',value:'advisory'},{label:'脆弱性',value:'vulnerability'}]" />
        </div>
        <div class="col-12 row justify-end">
          <q-btn color="primary" unelevated type="submit" icon="schedule" label="スケジュールを追加" :loading="busy === 'schedule'" />
        </div>
      </q-form>
      <div v-if="loading" class="empty-state" role="status">スケジュールを読み込んでいます。</div>
      <div v-else-if="!dataReady" class="empty-state" role="status">スケジュールを取得できません。</div>
      <div v-else-if="!schedules.length" class="empty-state">スケジュールはまだありません。</div>
      <div v-else class="schedule-list">
        <div v-for="schedule in schedules" :key="schedule.id" class="schedule-row">
          <div class="schedule-main">
            <div class="text-weight-bold">{{ schedule.cadence === 'daily' ? '毎日' : '毎週' }} {{ schedule.local_time }}（{{ schedule.timezone }}）</div>
            <div class="run-meta">{{ categoryLabel(schedule.parameters.category ?? null) }} · 次回 {{ dateLabel(schedule.next_slot_at) }}</div>
            <div class="run-meta">ID: {{ schedule.id }}</div>
          </div>
          <q-toggle :model-value="schedule.enabled" :label="schedule.enabled ? '有効' : '停止中'"
            :disable="busy === `schedule:${schedule.id}`" @update:model-value="toggleSchedule(schedule)" />
        </div>
        <div v-if="nextScheduleCursor" class="row justify-center q-mt-md">
          <q-btn flat color="primary" icon="expand_more" label="古いスケジュールをさらに読み込む"
            :loading="loadingOlderSchedules" @click="loadOlderSchedules" />
        </div>
      </div>
    </section>
  </q-page>
</template>

<style scoped>
.report-admin section { overflow: hidden; }
.run-sync-time { color: var(--nous-muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.report-run-filters { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; padding: 10px 17px; border-bottom: 1px solid var(--nous-line); }
.report-run-filter { min-height: 36px; padding: 6px 12px; background: none; border: 1px solid transparent; border-radius: 3px; color: var(--nous-muted); cursor: pointer; font: inherit; font-size: 12px; font-weight: 650; }
.report-run-filter:hover { border-color: var(--nous-line); }
.report-run-filter.active { color: var(--nous-ink); background: var(--nous-accent-wash); border-color: var(--nous-line); }
.report-run-filter-count { margin-left: auto; color: var(--nous-muted); font-size: 12px; font-variant-numeric: tabular-nums; }
.report-run-empty { min-height: 95px; font-size: 13px; }
.report-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.section-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 19px 22px; border-bottom: 1px solid var(--nous-line); }
.report-form-wrap { padding: 0 22px 22px; }
.report-template-tabs { border-bottom: 1px solid var(--nous-line); }
.report-form { max-width: 980px; }
.schedule-form { padding: 20px 22px 8px; }
.run-grid { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(280px, .8fr); }
.run-list { min-width: 0; }
.run-row { width: 100%; display: flex; gap: 16px; align-items: center; justify-content: space-between; padding: 17px 22px; border: 0; border-bottom: 1px solid var(--nous-line); background: transparent; color: inherit; text-align: left; cursor: pointer; }
.run-row:hover, .run-row:focus-visible, .run-row.selected { background: var(--nous-hover); }
.run-row:focus-visible { outline: 2px solid #4e9565; outline-offset: -2px; }
.run-row-main { min-width: 0; display: flex; flex-direction: column; gap: 4px; }
.run-title { font-size: 14px; font-weight: 650; }
.run-meta { color: var(--nous-muted); font-size: 11px; line-height: 1.7; overflow-wrap: anywhere; }
.run-state { flex: 0 0 auto; border-radius: 999px; padding: 4px 9px; font-size: 11px; font-weight: 700; background: var(--nous-hover); }
.state-published { color: #237044; background: #e8f5ea; }
.state-failed { color: #9c2f2f; background: #fff0ee; }
.state-skipped, .state-cancelled { color: var(--nous-muted); }
.body--dark .state-published { color: #a4deb1; background: #294331; }
.body--dark .state-failed { color: #ffaaa1; background: #4b2927; }
.run-detail { min-width: 0; padding: 20px; border-left: 1px solid var(--nous-line); background: var(--nous-paper); }
.run-detail-empty { display: grid; place-items: center; }
.detail-line { display: grid; grid-template-columns: 92px minmax(0,1fr); gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--nous-line); font-size: 12px; overflow-wrap: anywhere; }
.detail-line > span:first-child { color: var(--nous-muted); }
.stage-line { display: flex; justify-content: space-between; gap: 12px; padding: 5px 0; border-bottom: 1px solid var(--nous-line); font-size: 11px; }
.event-timeline { list-style: none; padding: 0; margin: 0; max-height: 420px; overflow: auto; }
.event-row { padding: 9px 0; border-bottom: 1px solid var(--nous-line); font-size: 11px; overflow-wrap: anywhere; }
.event-row.event-failed { color: var(--q-negative); }
.event-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
.event-heading > span, .event-meta { color: var(--nous-muted); font-size: 10px; line-height: 1.6; }
.event-code { font-family: monospace; font-weight: 700; }
.schedule-list { border-top: 1px solid var(--nous-line); }
.schedule-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 18px 22px; border-bottom: 1px solid var(--nous-line); }
.schedule-main { min-width: 0; overflow-wrap: anywhere; }
@media (max-width: 900px) { .run-grid { grid-template-columns: minmax(0,1fr); } .run-detail { border-left: 0; border-top: 1px solid var(--nous-line); } }
@media (max-width: 600px) { .report-stats { gap: 6px; } .section-heading, .report-form-wrap, .schedule-form { padding-left: 15px; padding-right: 15px; } .section-heading { padding-top: 16px; padding-bottom: 16px; } .run-row { align-items: flex-start; padding: 15px; } .schedule-row { padding: 15px; } .run-state { white-space: nowrap; } }
</style>
