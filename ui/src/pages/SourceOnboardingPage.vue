<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../lib/api'

type SourceKind = 'rss' | 'json_api' | 'html'
type ItemKind = 'job_posting' | 'news' | 'advisory' | 'vulnerability' | 'company_update'

const sourceId = ref('')
const sourceUrl = ref('')
const sourceKind = ref<SourceKind>('rss')
const itemKind = ref<ItemKind>('advisory')
const organization = ref('')
const interval = ref(360)
const hourlyLimit = ref(4)
const concurrent = ref(1)
const reviewedAt = ref('')
const termsUrl = ref('')
const robotsUrl = ref('')
const note = ref('')
const jsonPath = ref('')
const fieldMapping = ref('')
const htmlItem = ref('')
const htmlTitle = ref('')
const htmlUrl = ref('')
const known = ref<string[]>([])
const knownError = ref(false)
const copied = ref(false)
onMounted(() => {
  void api.sources().then(items => { known.value = items.map(item => item.id) })
    .catch(() => { knownError.value = true })
})

const idPattern = /^[a-z][a-z0-9-]{2,99}$/
const duplicate = computed(() => known.value.includes(sourceId.value.trim()))
function isHttps(raw: string): boolean {
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' && !!url.hostname && !url.username && !url.password
  } catch { return false }
}
function mapLines(raw: string): Record<string, string> | null {
  const result: Record<string, string> = {}
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue
    const index = line.indexOf('=')
    const key = line.slice(0, index).trim()
    const value = line.slice(index + 1).trim()
    if (index < 1 || !['id', 'url', 'title', 'published', 'updated'].includes(key) ||
      !value || Object.prototype.hasOwnProperty.call(result, key)) return null
    result[key] = value
  }
  return result
}
const fields = computed(() => mapLines(fieldMapping.value))
const problems = computed(() => {
  const issues: string[] = []
  if (!idPattern.test(sourceId.value.trim())) issues.push('IDは英小文字で始まる3〜100文字（英小文字・数字・ハイフン）にしてください。')
  if (duplicate.value) issues.push('このIDはすでに登録されています。')
  if (!isHttps(sourceUrl.value.trim())) issues.push('HTTPSの取得先URLが必要です。')
  if (!['job_posting', 'news', 'advisory', 'vulnerability', 'company_update'].includes(itemKind.value)) issues.push('情報種別が不正です。')
  if (!Number.isInteger(interval.value) || interval.value < 15) issues.push('収集間隔は15分以上にしてください。')
  if (!Number.isInteger(hourlyLimit.value) || hourlyLimit.value < 1 || hourlyLimit.value > 60) issues.push('時間当たりの最大リクエスト数は1〜60です。')
  if (!Number.isInteger(concurrent.value) || concurrent.value < 1 || concurrent.value > 4) issues.push('同時取得数は1〜4です。')
  if (!/^\d{4}-\d{2}-\d{2}$/.test(reviewedAt.value) ||
      Number.isNaN(Date.parse(reviewedAt.value))) issues.push('利用条件を確認した日付を入力してください。')
  if (!note.value.trim()) issues.push('利用条件と保存範囲の確認内容を記載してください。')
  if (termsUrl.value.trim() && !isHttps(termsUrl.value.trim())) issues.push('利用規約URLはHTTPSにしてください。')
  if (robotsUrl.value.trim() && !isHttps(robotsUrl.value.trim())) issues.push('robots.txt URLはHTTPSにしてください。')
  if (sourceKind.value === 'json_api' && fields.value === null) issues.push('JSONフィールド対応表は key=field の形式です。')
  if (sourceKind.value === 'html' && (!htmlItem.value.trim() || !htmlTitle.value.trim() || !htmlUrl.value.trim())) issues.push('HTMLは項目・タイトル・リンクのCSSセレクタが必要です。')
  return issues
})
const ready = computed(() => problems.value.length === 0)
const quote = (v: string): string => JSON.stringify(v.trim())
const yaml = computed(() => {
  if (!ready.value) return ''
  const lines = [
    `id: ${sourceId.value.trim()}`,
    `kind: ${sourceKind.value}`,
    `url: ${quote(sourceUrl.value)}`,
    `adapter: ${sourceKind.value === 'rss' ? 'rss_v1' : sourceKind.value === 'json_api' ? 'json_v1' : 'html_v1'}`,
    `item_kind: ${itemKind.value}`,
  ]
  if (organization.value.trim()) lines.push(`organization: ${quote(organization.value)}`)
  lines.push(
    `interval_minutes: ${interval.value}`,
    `max_requests_per_hour: ${hourlyLimit.value}`,
    `max_concurrency: ${concurrent.value}`,
    'enabled: false',
    'policy:',
    `  reviewed_at: ${quote(reviewedAt.value)}`,
  )
  if (termsUrl.value.trim()) lines.push(`  terms_url: ${quote(termsUrl.value)}`)
  if (robotsUrl.value.trim()) lines.push(`  robots_url: ${quote(robotsUrl.value)}`)
  lines.push('  content_storage: metadata_only', `  note: ${quote(note.value)}`)
  if (sourceKind.value === 'json_api') {
    if (jsonPath.value.trim()) lines.push(`json_path: ${quote(jsonPath.value)}`)
    const mappings = Object.entries(fields.value ?? {})
    if (mappings.length) {
      lines.push('field_map:')
      for (const [key, value] of mappings) lines.push(`  ${key}: ${quote(value)}`)
    }
  }
  if (sourceKind.value === 'html') {
    lines.push('selectors:',
      `  item: ${quote(htmlItem.value)}`,
      `  title: ${quote(htmlTitle.value)}`,
      `  url: ${quote(htmlUrl.value)}`)
  }
  return lines.join('\n') + '\n'
})
const fileName = computed(() => `sources/${sourceId.value.trim()}.yaml`)
const githubUrl = computed(() => {
  const p = new URLSearchParams({ filename: fileName.value, value: yaml.value })
  return `https://github.com/yohn-jp/nous-osint/new/main?${p.toString()}`
})
async function copyYaml() {
  if (!ready.value) return
  try {
    await navigator.clipboard.writeText(yaml.value)
    copied.value = true
  } catch { copied.value = false }
}
function saveFile() {
  if (!ready.value) return
  const url = URL.createObjectURL(new Blob([yaml.value], { type: 'text/yaml;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `${sourceId.value.trim()}.yaml`
  link.click()
  URL.revokeObjectURL(url)
}
function openProposal() {
  if (!ready.value) return
  window.open(githubUrl.value, '_blank', 'noopener,noreferrer')
}
</script>

<template>
  <q-page class="nous-page">
    <div class="eyebrow q-mb-sm">INTELLIGENCE / SOURCE ONBOARDING</div>
    <div class="row items-center justify-between q-mb-sm">
      <h1 class="page-title q-ma-none">公式情報源を提案する。</h1>
      <q-btn flat icon="arrow_back" color="primary" label="情報源一覧" to="/sources" />
    </div>
    <p class="page-subtitle q-mb-lg">
      公式カタログへの追加用YAMLを作成します。GitHubでのレビュー・検証を経て反映され、この画面では収集は開始されません。
    </p>
    <div class="onboarding-grid">
      <section class="content-panel q-pa-lg">
        <div class="text-weight-bold q-mb-md">1. 情報源</div>
        <div class="row q-col-gutter-md q-mb-md">
          <div class="col-12 col-sm-6"><q-input v-model.trim="sourceId" outlined dense label="ソースID *" hint="例: vendor-security-advisories" /></div>
          <div class="col-12 col-sm-6"><q-select v-model="sourceKind" :options="[{ label: 'RSS / Atom', value: 'rss' }, { label: 'JSON API', value: 'json_api' }, { label: 'HTML', value: 'html' }]" emit-value map-options outlined dense label="取得方式" /></div>
          <div class="col-12"><q-input v-model.trim="sourceUrl" outlined dense label="取得URL（HTTPS）*" type="url" /></div>
          <div class="col-12 col-sm-6"><q-select v-model="itemKind" :options="[{label:'求人',value:'job_posting'},{label:'ニュース',value:'news'},{label:'注意喚起',value:'advisory'},{label:'脆弱性',value:'vulnerability'},{label:'企業動向',value:'company_update'}]" emit-value map-options outlined dense label="情報種別" /></div>
          <div class="col-12 col-sm-6"><q-input v-model.trim="organization" outlined dense label="組織名" /></div>
        </div>
        <template v-if="sourceKind === 'json_api'">
          <div class="text-weight-bold q-mb-sm">JSON抽出</div>
          <q-input v-model.trim="jsonPath" outlined dense label="配列へのパス（例: results.items）" class="q-mb-md" />
          <q-input v-model="fieldMapping" outlined type="textarea" autogrow label="フィールド対応（1行につき title=name など）" hint="id / url / title / published / updated を利用できます。" class="q-mb-lg" />
        </template>
        <template v-if="sourceKind === 'html'">
          <div class="text-weight-bold q-mb-sm">HTMLセレクタ</div>
          <q-input v-model.trim="htmlItem" outlined dense label="項目（例: article）*" class="q-mb-md" />
          <q-input v-model.trim="htmlTitle" outlined dense label="タイトル（例: h2）*" class="q-mb-md" />
          <q-input v-model.trim="htmlUrl" outlined dense label="リンク（例: a）*" class="q-mb-lg" />
        </template>
        <q-separator class="q-my-lg" />
        <div class="text-weight-bold q-mb-md">2. 収集予算</div>
        <div class="row q-col-gutter-md q-mb-md">
          <div class="col-12 col-sm-4"><q-input v-model.number="interval" type="number" outlined dense label="間隔（分）" /></div>
          <div class="col-12 col-sm-4"><q-input v-model.number="hourlyLimit" type="number" outlined dense label="最大要求/時" /></div>
          <div class="col-12 col-sm-4"><q-input v-model.number="concurrent" type="number" outlined dense label="同時取得" /></div>
        </div>
        <q-separator class="q-my-lg" />
        <div class="text-weight-bold q-mb-md">3. 利用条件の確認</div>
        <q-input v-model="reviewedAt" type="date" outlined dense label="確認日 *" stack-label class="q-mb-md" />
        <q-input v-model.trim="termsUrl" outlined dense label="利用規約URL" class="q-mb-md" />
        <q-input v-model.trim="robotsUrl" outlined dense label="robots.txt URL" class="q-mb-md" />
        <q-input v-model="note" type="textarea" outlined autogrow label="確認内容・保存条件 *" hint="自動的に適法性を保証するものではありません。保存はメタデータのみです。" />
      </section>
      <section class="content-panel q-pa-lg onboarding-review">
        <div class="text-weight-bold q-mb-sm">4. レビュー用の定義</div>
        <p class="text-caption text-grey-7">有効化は別途レビューで行います。初期状態は常に disabled です。</p>
        <q-banner v-if="knownError" rounded class="bg-orange-1 text-brown-9 q-mb-md">登録済みIDを確認できませんでした。Git側でも重複検査されます。</q-banner>
        <q-banner v-if="!ready" rounded class="q-mb-md bg-grey-2 text-grey-9">
          <div v-for="problem in problems" :key="problem" class="q-mb-xs">{{ problem }}</div>
        </q-banner>
        <pre class="onboarding-code" aria-label="生成されるソースYAML">{{ yaml || '必要な情報を入力すると登録定義が表示されます。' }}</pre>
        <div class="row q-gutter-sm q-mt-md">
          <q-btn :disable="!ready" outline color="primary" icon="content_copy" :label="copied ? 'コピー済み' : 'YAMLをコピー'" @click="copyYaml" />
          <q-btn :disable="!ready" outline color="primary" icon="download" label="YAMLを保存" @click="saveFile" />
          <q-btn :disable="!ready" color="primary" unelevated icon="open_in_new" label="GitHubでファイルを作成" @click="openProposal" />
        </div>
        <p class="text-caption text-grey-7 q-mt-lg">
          GitHubのファイル作成画面が開きます。別ブランチへコミットしてPRを作成してください。PRのCIで定義を検証し、
          Source Probeワークフローで実データを確認した後に有効化・マージします。
          承認された定義は次回アプリイメージに含まれます。
        </p>
      </section>
    </div>
  </q-page>
</template>
