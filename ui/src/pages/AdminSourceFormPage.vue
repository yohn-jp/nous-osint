<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, type SourceDefinition } from '../lib/api'
const route = useRoute()
const router = useRouter()
const editId = computed(() => typeof route.params.id === 'string' ? route.params.id : '')
const editing = computed(() => !!editId.value)
const id = ref('')
const kind = ref<'rss' | 'json_api' | 'html'>('rss')
type JsonAdapter = 'json_v1' | 'greenhouse_jobs_v1' | 'lever_jobs_v1' | 'ashby_jobs_v1' | 'x_user_posts_v1'
const jsonAdapter = ref<JsonAdapter>('json_v1')
const nativeJobAdapter = computed(() => kind.value === 'json_api' &&
  ['greenhouse_jobs_v1', 'lever_jobs_v1', 'ashby_jobs_v1'].includes(jsonAdapter.value))
const maxPages = ref(1)
const url = ref('')
const itemKind = ref<SourceDefinition['item_kind']>('advisory')
const organization = ref('')
const sourceCategory = ref<string | null>(null)
const categoryOptions = [
  { label: 'データ種別に応じて自動分類', value: null },
  { label: '脆弱性データベース', value: 'vulnerability' },
  { label: '公式アドバイザリ', value: 'advisory' },
  { label: '脅威・攻撃調査', value: 'threat_research' },
  { label: 'セキュリティ動向', value: 'security_news' },
  { label: '企業・業界動向', value: 'industry' },
  { label: '求人情報', value: 'careers' },
]
const interval = ref(360)
const hourly = ref(4)
const concurrent = ref(1)
const enabled = ref(false)
const reviewedAt = ref('')
const termsUrl = ref('')
const robotsUrl = ref('')
const note = ref('')
const jsonPath = ref('')
const fieldMap = ref('') // canonical_field=publisher_field, one per line
const htmlItem = ref('')
const htmlTitle = ref('')
const htmlUrl = ref('')
const saving = ref(false)
const loading = ref(false)
const error = ref('')

function linesToMap(raw: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue
    const parts = line.split('=')
    if (parts.length !== 2) throw new Error('フィールド対応は 1行1件の name=source_field 形式で指定してください。')
    const [key, value] = parts.map(s => s.trim())
    if (!key || !value || !['id', 'title', 'url', 'published', 'updated'].includes(key) ||
        Object.prototype.hasOwnProperty.call(result, key)) {
      throw new Error('JSONのフィールド対応に不正・重複したキーがあります。')
    }
    result[key] = value
  }
  return result
}

onMounted(async () => {
  if (!editing.value) return
  loading.value = true
  try {
    const source = (await api.adminSources()).find(s => s.id === editId.value)
    if (!source || source.origin !== 'custom') throw new Error('編集可能な独自ソースがありません。')
    const c = source.config
    id.value = c.id
    kind.value = c.kind
    if (['json_v1', 'greenhouse_jobs_v1', 'lever_jobs_v1', 'ashby_jobs_v1', 'x_user_posts_v1'].includes(c.adapter)) {
      jsonAdapter.value = c.adapter as JsonAdapter
    }
    maxPages.value = c.max_pages ?? 1
    url.value = c.url
    itemKind.value = c.item_kind
    organization.value = c.organization || ''
    sourceCategory.value = c.category || null
    interval.value = c.interval_minutes
    hourly.value = c.max_requests_per_hour
    concurrent.value = c.max_concurrency
    enabled.value = c.enabled
    reviewedAt.value = c.policy.reviewed_at
    termsUrl.value = c.policy.terms_url || ''
    robotsUrl.value = c.policy.robots_url || ''
    note.value = c.policy.note
    jsonPath.value = c.json_path || ''
    fieldMap.value = Object.entries(c.field_map ?? {}).map(([k, v]) => k + '=' + v).join('\n')
    htmlItem.value = c.selectors?.item || ''
    htmlTitle.value = c.selectors?.title || ''
    htmlUrl.value = c.selectors?.url || ''
  } catch (e) { error.value = e instanceof Error ? e.message : '取得できませんでした。' }
  finally { loading.value = false }
})

async function submit() {
  error.value = ''
  saving.value = true
  try {
    const config: SourceDefinition = {
      id: id.value.trim(), kind: kind.value, url: url.value.trim(),
      adapter: kind.value === 'rss' ? 'rss_v1' : kind.value === 'json_api' ? jsonAdapter.value : 'html_v1',
      item_kind: nativeJobAdapter.value ? 'job_posting' : jsonAdapter.value === 'x_user_posts_v1' && kind.value === 'json_api' ? 'news' : itemKind.value,
      interval_minutes: interval.value,
      max_requests_per_hour: hourly.value, max_concurrency: concurrent.value,
      max_pages: kind.value === 'json_api' && (jsonAdapter.value === 'lever_jobs_v1' || jsonAdapter.value === 'x_user_posts_v1') ? maxPages.value : 1,
      enabled: editing.value ? enabled.value : false,
      policy: {
        reviewed_at: reviewedAt.value,
        terms_url: termsUrl.value.trim() || null,
        robots_url: robotsUrl.value.trim() || null,
        content_storage: 'metadata_only', note: note.value.trim(),
      },
    }
    if (organization.value.trim()) config.organization = organization.value.trim()
    if (sourceCategory.value) config.category = sourceCategory.value
    if (kind.value === 'json_api' && jsonAdapter.value === 'json_v1') {
      config.json_path = jsonPath.value.trim() || null
      config.field_map = linesToMap(fieldMap.value)
    }
    if (kind.value === 'html') {
      config.selectors = { item: htmlItem.value.trim(), title: htmlTitle.value.trim(), url: htmlUrl.value.trim() }
    }
    if (editing.value) await api.adminUpdate(editId.value, config)
    else await api.adminCreate(config)
    await router.push('/admin/sources')
  } catch (e) { error.value = e instanceof Error ? e.message : '登録できませんでした。' }
  finally { saving.value = false }
}
</script>

<template>
  <q-page class="nous-page source-form-page">
    <div class="row items-center justify-between q-gutter-sm q-mb-sm">
      <h1 class="page-title q-ma-none">{{ editing ? '独自ソースの編集' : '独自ソースの追加' }}</h1>
      <q-btn flat color="primary" icon="arrow_back" label="管理画面に戻る" to="/admin/sources" />
    </div>
    <p class="page-subtitle q-mb-lg">GitHubを使わず、このNousインスタンスに登録します。新規ソースは停止状態で作成されます。</p>
    <q-banner v-if="error" class="bg-red-1 text-negative q-mb-md" role="alert">{{ error }}</q-banner>
    <q-form class="content-panel admin-form" @submit.prevent="submit">
      <div class="text-weight-bold q-mb-md">情報源の識別と取得方式</div>
      <div class="row q-col-gutter-md">
        <div class="col-12 col-sm-6"><q-input v-model.trim="id" outlined dense label="ソースID *" :disable="editing || loading" :rules="[v => /^[a-z][a-z0-9-]{2,99}$/.test(v) || '英小文字で始まる英小文字・数字・ハイフン3〜100文字']" /></div>
        <div class="col-12 col-sm-6"><q-select v-model="kind" outlined dense label="方式" emit-value map-options :options="[{label:'RSS / Atom',value:'rss'},{label:'JSON API',value:'json_api'},{label:'HTML',value:'html'}]" /></div>
        <div class="col-12"><q-input v-model.trim="url" outlined dense type="url" label="公開HTTPS URL *" :rules="[v => /^https:\/\/[^\s/]+/.test(v) || 'HTTPS URLを入力してください']" /></div>
        <div class="col-12 col-sm-6"><q-select v-model="itemKind" outlined dense label="種別" emit-value map-options :options="[{label:'求人',value:'job_posting'},{label:'ニュース',value:'news'},{label:'注意喚起',value:'advisory'},{label:'脆弱性',value:'vulnerability'},{label:'企業動向',value:'company_update'}]" /></div>
        <div class="col-12 col-sm-6"><q-input v-model.trim="organization" outlined dense label="提供組織（任意）" maxlength="200" /></div>
        <div class="col-12"><q-select v-model="sourceCategory" outlined dense label="情報源カテゴリ" clearable
          emit-value map-options :options="categoryOptions" hint="記事のデータ種別とは独立したテーマ分類です。" /></div>
      </div>
      <template v-if="kind === 'json_api'">
        <div class="text-weight-bold q-mt-lg q-mb-md">JSONの抽出方式</div>
        <q-select v-model="jsonAdapter" outlined dense emit-value map-options class="q-mb-md"
          :options="[{label:'一般JSON',value:'json_v1'},{label:'Greenhouse 公開求人（国内セキュリティ）',value:'greenhouse_jobs_v1'},{label:'Lever 公開求人（国内セキュリティ）',value:'lever_jobs_v1'},{label:'Ashby 公開求人（国内セキュリティ）',value:'ashby_jobs_v1'},{label:'X 公式API（公開アカウント投稿・従量課金）',value:'x_user_posts_v1'}]" />
        <template v-if="jsonAdapter === 'json_v1'">
          <q-input v-model.trim="jsonPath" outlined dense label="配列へのパス（例: results.items）" class="q-mb-md" />
          <q-input v-model="fieldMap" outlined autogrow type="textarea" label="フィールド対応" hint="例: id=uuid、title=headline。1行に1項目。" />
        </template>
        <q-banner v-else-if="jsonAdapter === 'x_user_posts_v1'" class="q-mb-md">
          X公式APIのユーザーIDを使い、URLは <code>https://api.x.com/2/users/123456789/tweets</code> 形式で入力します。
          認証トークンと1日あたりの取得上限をサーバー側に設定するまで課金APIは呼び出されません。
          対象は公開投稿のみで、返信・リポスト・本文全文・添付メディアは保存しません。
        </q-banner>
        <q-banner v-else class="bg-grey-2 text-grey-9 q-mb-md">
          提供元の公式公開GETエンドポイントのみ対応します。国内勤務地と技術系セキュリティ職種を判定し、求人本文は保存しません。
          募集終了は確認済みの完全取得時だけ反映します。
        </q-banner>
        <q-input v-if="jsonAdapter === 'lever_jobs_v1' || jsonAdapter === 'x_user_posts_v1'" v-model.number="maxPages" type="number"
          outlined dense :label="jsonAdapter === 'x_user_posts_v1' ? '最大ページ数（1〜3・1ページ最大10投稿）' : '最大ページ数（1〜10・1ページ100件）'"
          :rules="[v => Number.isInteger(v) && v >= 1 && v <= (jsonAdapter === 'x_user_posts_v1' ? 3 : 10) && v <= hourly || '最大ページ数は上限以内かつ時間あたり要求数以下']" />
      </template>
      <template v-if="kind === 'html'">
        <div class="text-weight-bold q-mt-lg q-mb-md">HTMLのCSSセレクタ</div>
        <q-input v-model.trim="htmlItem" outlined dense label="項目 *" class="q-mb-md" />
        <q-input v-model.trim="htmlTitle" outlined dense label="タイトル *" class="q-mb-md" />
        <q-input v-model.trim="htmlUrl" outlined dense label="リンク *" />
      </template>
      <q-separator class="q-my-lg" />
      <div class="text-weight-bold q-mb-md">収集予算</div>
      <div class="row q-col-gutter-md">
        <div class="col-12 col-sm-4"><q-input v-model.number="interval" type="number" outlined dense label="取得間隔（分）" :rules="[v => Number.isInteger(v) && v >= 15 || '15分以上']" /></div>
        <div class="col-12 col-sm-4"><q-input v-model.number="hourly" type="number" outlined dense label="最大要求／時" :rules="[v => Number.isInteger(v) && v >= 1 && v <= 60 || '1〜60']" /></div>
        <div class="col-12 col-sm-4"><q-input v-model.number="concurrent" type="number" outlined dense label="同時取得数" :rules="[v => Number.isInteger(v) && v >= 1 && v <= 4 || '1〜4']" /></div>
      </div>
      <q-separator class="q-my-lg" />
      <div class="text-weight-bold q-mb-md">提供元の利用条件・保存方針</div>
      <q-input v-model="reviewedAt" outlined dense type="date" stack-label label="確認日 *" class="q-mb-md" :rules="[v => !!v || '確認日が必要です']" />
      <q-input v-model.trim="termsUrl" outlined dense label="利用条件URL（任意）" class="q-mb-md" />
      <q-input v-model.trim="robotsUrl" outlined dense label="robots.txt URL（任意）" class="q-mb-md" />
      <q-input v-model.trim="note" outlined autogrow type="textarea" label="確認内容 *" hint="本文は保存せずメタデータのみ収集します。到達性は利用許可を意味しません。" :rules="[v => !!v.trim() || '確認内容が必要です']" />
      <div class="row items-center justify-end q-gutter-sm q-mt-lg">
        <q-btn flat color="primary" label="キャンセル" to="/admin/sources" />
        <q-btn color="primary" unelevated type="submit" :loading="saving || loading" :disable="loading" :label="editing ? '変更を保存' : '停止状態で登録'" />
      </div>
    </q-form>
  </q-page>
</template>
