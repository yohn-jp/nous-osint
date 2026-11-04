# Nous OSINT — Automated Intelligence Reports

Status: **implementation design / not yet implemented**  
Date: **2026-11-04**  
Authority: [ARCHITECTURE.md](ARCHITECTURE.md), [DATA_MODEL.md](DATA_MODEL.md), [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [REMOTE_MCP_ACCESS.md](REMOTE_MCP_ACCESS.md), [SOURCE_LICENSES.md](SOURCE_LICENSES.md), [CVE_KEV_CORRELATION.md](CVE_KEV_CORRELATION.md)

## 1. Goal and decisions

Nous OSINT に、取得済みの公開情報から**利用者向けの品質の高い記事を自動生成し、Cloudflare Access 配下で公開する**機能を追加する。記事生成は既存の収集基盤の代替ではなく、出典付きの派生物である。初期実装は単一 VM のセルフホストを基準とする。

- **利用モード**: (A) スケジュールによる自動実行、(B) UI からの随時実行。テーマ・期間・識別子等は**テンプレートの検証済みパラメータ**として両モードから指定する。任意プロンプト入力・任意 URL 取材は MVP 対象外。
- **編集工程**: 企画 → 事実検証 → 執筆 → 推敲。その後、決定論的な最終検査を通った場合だけ**人間の承認なし**で公開する。掲載価値がなければ `skipped` とし、穴埋め記事を生成しない。
- **AI ハーネス**: VM 上で所有者が正規に認証した **公式 Codex CLI** の `codex exec` を専用 Worker から非対話実行する。サブスクリプションの認証情報は Nous にコピーしない。モデル・利用上限・利用可能な認証方式は実行時に確認し、保証しない。Pi への差し替えは後続候補であり、初期導入に必要ない。
- **出版**: **Astro の静的 HTML ビルド**を選択する。記事の意味構造だけを Codex に生成させ、デザイン・HTML テンプレート・リンクとコンポーネントは Git 管理の固定実装とする。SSR、常駐 Node サーバ、独立した CMS、メッセージブローカーを追加しない。
- **公開先**: 既存 `https://nous.yohn.jp/reports/` の**同一オリジン・同一 Access アプリケーション**。既存 Quasar は収集 UI・実行管理 UI として維持する。記事は DB と VM 内の private volume に置き、公開 Git リポジトリへ生成記事や原資料をコミットしない。
- **正本**: Git = コード、テンプレート、スキーマ、デザイン。PostgreSQL = 実行設定・ジョブ・記事メタデータ・証跡。専用 volume = HTML ビルド成果物。元 `items` と immutable `item_versions` は変更しない。

### 非目標

公開インターネット向けの記事配信、編集者の承認ワークフロー、ブラウザ WYSIWYG、任意テーマでの自由調査、ソースの利用条件に反する本文転載、推論を観測事実として扱うこと、Codex 認証サービスの再実装、Nous の Quasar を Astro に移植すること、モデル学習・独自エージェントフレームワークの開発は実施しない。

## 2. 既存実装との接続点

2026-11-04 時点の `main` (`9414592b7044a475efa954b72c5d2b57e0e2801c`) を調査済み。

- `src/nous/models.py`: `Source` / `Item` / `ItemVersion` / `CveItemLink`、最新 Alembic `0007`。既存 `fetch_jobs` は取得専用のためレポートジョブと混用しない。
- `src/nous/api.py`: 読み取り専用検索、changes、`GET /v1/cves/{cve_id}`。CVE/KEV の状態は `listed | not_listed | unknown` を厳密に維持する。
- `src/nous/admin.py`: Access subject allowlist と専用 SQL 接続で管理書き込みを提供。レポート実行管理もこの権限境界で提供する。
- `src/nous/access_auth.py`, `remote_gateway.py`: JWT 検証、明示的 HTTP パス・メソッド許可、Quasar の厳密な SPA fallback。`/reports/` と管理 API の追加には**両方の allowlist とルーティング**の更新が必須。MCP は読み取り専用のまま維持する。
- `ui/`: Quasar 2/Vue 3 SPA。ナビゲーションに Reports と生成ジョブ管理を加えるが、記事本体のレンダラーにはしない。
- `deploy/quadlet/`: rootless Podman + PostgreSQL + singleton scheduler/worker + MCP/API/Tunnel。PostgreSQL を外部公開しない。VM に新しい Node/SSR 常駐プロセスを置かない。

## 3. 処理と責務

```text
Official & custom approved sources
       | existing scheduler / adapters / history
       v
PostgreSQL: items / item_versions / cve_item_links
       | read-only snapshot, bounded and source-policy aware
       v
Report scheduler + UI on-demand enqueue ----> report_runs (durable SQL queue)
                                              |
                                     lease / retry / timeout
                                              v
                                   Report Worker (rootless)
                                   1) evidence bundle
                                   2) Codex: planning
                                   3) Codex: fact verification
                                   4) Codex: drafting
                                   5) Codex: editing
                                   6) deterministic validation
                                              |
                                    structured article + Markdown
                                              v
                                  Astro static build (one-shot)
                                  validate links/assets/HTML
                                              |
                                    atomic release promotion
                                              v
                      private read-only volume -> MCP/UI gateway
                                     /reports/* via Access
```

**Report Worker** は既存の取得 Worker と別のコマンド・別の Quadlet・別のイメージで動く。Python 側が SQL と Codex 実行を統括し、記事のビルド時だけ同じ専用 Worker イメージ内の Node/Astro を起動する。Podman ソケットをコンテナにマウントしない。Codex や Astro を毎回ダウンロードするのではなく、検証済みバージョンをビルド時に固定する。API・MCP 用イメージには Codex CLI やその認証情報を入れない。

MVP は単一 Report Worker（同時生成 1 件）。同一ループで期限到来した `report_schedules` の投入と `report_runs` の claim を行い、SQL 一意制約により再起動・二重 tick を無害化する。後のスケール時にスケジューラを分離しても DB 契約は変えない。

## 4. テンプレート仕様

レビュー済みの `reports/templates/*.yaml` を Git 正本とする。`template_id` と `revision` は必須で、実行中にテンプレートが更新されてもジョブは保存済み revision の入力に固定される。テンプレートは特定の情報領域に依存しない schema/processor と、テーマごとの source selector / editorial policy を分離する。

必須属性: `id`, `revision`, `title`, `category`, `parameters_schema`, `source_selector`, `window_policy`, `evidence_limits`, `outline`, `quality_rules`, `publish_policy`。未知キーを拒否し、テンプレート単位で参照元種類、生成できる本文ブロック、タイトル・要旨・文字数、根拠の鮮度を定義する。テンプレートから任意の shell command、任意 SQL、ネットワークアクセス先、プロンプト内のシステム設定を指定できない。

### 初期 2 テンプレート

| ID | 入力 | 基本構成 | 用途 |
| --- | --- | --- | --- |
| `security-daily` | 対象日（IANA タイムゾーン、デフォルト `Asia/Tokyo`）、任意の許可済みカテゴリ | 概況、重要変化、根拠と対応上の論点、出典 | 定期・随時 |
| `cve-kev-deep-dive` | **正規化された CVE ID**、任意の観測期間 | CVE 概要、KEV 状態と観測時刻、関連一次情報、影響・未確認事項、出典 | 随時、将来自動対象選定 |

`security-weekly`、求人・企業・技術トレンドは同一構造で追加可能とし、MVP の実装受入には含めない。生成対象のレコードが存在しない、根拠が弱い、ソースポリシーで再利用できない場合は `skipped` / `failed_validation` として未公開にする。

### 入力の制限

- 日付・期間は明示的な開始/終了（UTC 保存）に正規化する。日次の境界は指定 IANA タイムゾーンの日付から計算し、実行時刻によって途中で変えない。
- CVE は既存 `valid_cve_id()` で厳密に検証。`KEV=unknown` や `not_listed` を「悪用されていない」と表現しない。タイトル中の CVE 文字列だけで脆弱性の存在や悪用を断定しない。
- 初期上限の例: 90 日までの期間、1 ジョブ 200 観測レコード、1 件の本文への出典 50 件、入力 bundle 最大 2 MiB。上限値は定数または検証済み構成として確定し、UI・API・Worker で一致させる。

## 5. Evidence Bundle（生成への唯一の事実入力）

Worker は確定した `observed_cutoff` を持つ読み取り専用 SQL トランザクションで、`items`、指定時点で参照する `item_versions`、source の収集状態・許諾済みフィールド、CVE 関連情報を取得して**スナップショット**を作る。実装上の各 query はキーセットページングで全件取得を禁止し、ソース単位の上限・総上限をかける。過去レポートの再生成では、保存済み bundle/関連 `item_version_id` によって元情報を再現できるようにする。

Bundle のレコードには最低限 `evidence_id`, `source_key`, `item_id`, `item_version_id`, `relation`, `publisher_url`, `observed_at`, `published_at?`, `retrieved_at?`, `allowed_fields`, `content_policy` を含める。CVE/KEV はその時点で観測した状態と `catalog_as_of` を固定して記録する。生の第三者記事本文を無断コピーしない。許可されないソースの全文を Codex や記事に渡さない。

原資料の記載は**非信頼データ**であり、原資料内に「プロンプトを無視」「秘密情報を送信」「別 URL にアクセス」等の命令があっても処理命令として扱わない。Codex は原則として bundle 内だけを根拠に執筆し、勝手に外部取材を追加しない。bundle 自体とその SHA-256、入力パラメータ、テンプレート revision、抽出コード revision を保存する。

## 6. 編集工程と品質ゲート

| Stage | 入力 | 出力 | 制約・失敗時 |
| --- | --- | --- | --- |
| 企画 | template + evidence bundle | `plan.json`: 主題、対象読者、論点、使用 evidence ID、記事を作る理由 | 重要な変化がない場合 `skipped`。事実の創作禁止 |
| 検証 | plan + bundle | `fact_check.json`: 主張と evidence ID の対応、観測/推論区分、曖昧点、差し戻し | 出典なしの主要主張は採用しない。未検証は未検証とする |
| 執筆 | verified plan + bundle | `draft.json`: 構造化記事データ + 制限付き Markdown | 見出し・本文・表等はテンプレート許可ブロックのみ |
| 推敲 | draft + fact_check + bundle | `article.json`: 完成原稿 + claim/evidence map | 可読性・重複・論旨を改善するが新事実は追加しない |
| 公開前検査 | article + bundle + renderer output | 合否、検査レポート、生成 artifact hash | 不合格なら公開しない。検査は決定論的な fail-closed |

各 Codex 呼び出しは固定の役割プロンプト + JSON Schema を使用し、ステージごとに**別の実行**として成果物を保存する。構造化出力 API/CLI オプションの対応は採用 CLI バージョンで検証する。無制限な自律再帰・別エージェントへの権限委譲は行わない。有限回の修正（例: 1 回）で検査に通らなければ失敗とする。

最終検査は少なくとも以下を含む。

1. JSON Schema と必須セクション、文字数・段落数・許可コンポーネント・言語を検査。
2. **事実主張**の evidence ID が bundle に存在し、参照先の `item_version_id` / immutable hash と整合することを検査。引用先 URL のスキーム・ホスト・長さ等を検査し、改ざん・匿名の出典追加を拒否する。
3. KEV 三値と鮮度・CVE 一致、観測と推論の表示、日時・数値・比較対象期間の整合を検査。機械的に意味を完全証明できない部分は独立の検証工程でレビューし、検査済みという表示を過大に付けない。
4. 生 HTML、JavaScript、スタイル埋め込み、外部トラッキング、未承認画像、危険な URL を拒否する。Markdown を安全な AST から描画し、文字列を直接 HTML に挿入しない。
5. Astro ビルドが成功し、主要ページ・内部リンク・参照 ID・静的アセットが解決することを検査。失敗時は公開中の release に一切変更を加えない。

記事は「確認された事実」「その根拠からの分析・推論」「未確認」を文章上でも区別し、各出典に publisher 名、正規 URL、観測日を示す。生成モデルが正しいと自己申告しただけで事実確認完了とはしない。

## 7. 記事スキーマと固定デザイン

`reports/schemas/article-v1.schema.json` で以下のような**許可付きブロックモデル**を定義する。Codex は HTML/CSS/JS を出力できない。

```json
{
  "schema_version": 1,
  "template_id": "security-daily",
  "language": "ja",
  "title": "...",
  "dek": "...",
  "summary": ["..."],
  "sections": [
    {"heading": "...", "blocks": [
      {"type": "paragraph", "markdown": "...", "evidence_ids": ["E001"]},
      {"type": "source_list", "evidence_ids": ["E001"]}
    ]}
  ],
  "claims": [{"text": "...", "classification": "observed", "evidence_ids": ["E001"]}]
}
```

初期許可ブロックは `paragraph`, `bullet_list`, `fact_table`, `source_list`, `cve_fact`, `quote` に限定する。グラフは正規化された数値データと比較条件を扱えるようになってから追加。記事中に任意の Vue/MDX/HTML コンポーネントは埋め込まない。

Astro は `reports/site/` に置き、`static` output と記事 content collection / schema を利用する。共通の `ArticleLayout`、一覧、詳細、テンプレート別ラベル、出典リスト、CVE/KEV 状態部品、関連記事（明示的な関連だけ）を実装する。固定デザイントークンは Git 管理し、編集者風の可読性・長文幅・表・和文組版・モバイル・ダークモード・アクセシビリティを検証する。**CSS/コンポーネントは記事生成プロンプトが編集しない**。

公開 URL 例:

- `GET /reports/` — 全記事一覧（静的）。
- `GET /reports/security/2026-11-04-security-daily/` — 日次記事。
- `GET /reports/cve/CVE-2026-12345/` — CVE テーマ記事（同一 CVE の再刊は別 URL/slug とし上書きしない）。

静的記事 URL は `slug` を allowlist 正規化し衝突禁止。`sitemap.xml` 等の外部検索エンジン向け公開物は既定で生成しない。`noindex` と `Cache-Control: private, no-store` は多層防御であり、認証の代替ではない。

## 8. 永続化とジョブ契約

既存 `fetch_jobs` を変更せず、Alembic **0008**（既存 `0007` の後続）で新規モデルを追加する。想定テーブルは以下。列名・型は実装で最小限に整合させるが、**一意性と監査要件は変更しない**。

| テーブル | 正本として保持する内容 | 主な不変条件 |
| --- | --- | --- |
| `report_schedules` | template/revision、検証済み params、タイムゾーン、cadence、次回予定、enabled、作成 actor | next slot を UTC で確定。過去 slot を無制限 catch-up しない |
| `report_runs` | UUID、trigger(manual/scheduled)、template/revision、params、schedule slot、idempotency key、state、lease/attempt、入力 cutoff/hash、stage、error code、timestamps、生成 report_id | 同一 schedule + slot は一度だけ投入。実行 claim は排他的、期限切れ lease を回収 |
| `reports` | UUID、unique slug、article schema version、元 run ID、headline、要約、カテゴリ、published_at、artifact digest/path、supersedes ID、生成モデル/ハーネス version、input digest | 既刊データは不変。修正/再刊は新 UUID + supersedes。失敗時は既刊を維持 |
| `report_evidence` | report ID、evidence ID、item ID + **item_version ID**、source URL、観測日時、relation、出典種別 | 必ず元データの immutable version に解決し、関係を偽装しない |

中間生成物 (`plan`, `fact_check`, `draft`, `article`) と検査ログは非公開のジョブ領域に保存する。実行履歴のメタデータと最終 immutable 記事は DB に永続化し、ファイルを消しても再ビルド可能にする。巨大な raw bundle は private artifact volume に hash 付きで保存して参照し、DB にその hash と保管期限を保持する。記事への掲載が許されない本文は永続的に転載しない。

ジョブ状態: `queued → leased/running → validating → publishing → published`。合法的な終端として `skipped`, `failed`, `cancelled` を持つ。公開前の一時的な失敗は有限回 retry（初期最大 2 回）、検査失敗・不正入力は再試行せず失敗。実行時間の上限、lease heartbeat、途中停止時の cleanup、二重刊行を防ぐ unique key を設ける。Codex の実行制限・認証失効・予算不足は分かる error code として保存し、秘密情報はログに残さない。

## 9. API / UI

管理系は**既存の Access subject allowlist を必要条件**とし、既存 `admin.py` の権限境界を再利用。FastAPI と gateway の両方でメソッド/パス/JSON サイズ/各パラメータを検証し、ブラウザから任意のコマンド、プロンプト、SQL、外部 URL を受け取らない。

| Endpoint | 用途 |
| --- | --- |
| `GET /v1/admin/report-templates` | 実行可能テンプレートと許可パラメータを一覧 |
| `POST /v1/admin/report-runs` | `{template_id, parameters, idempotency_key?}` を検証して投入、`202 {run_id, state}` |
| `GET /v1/admin/report-runs` | 上限・ページング付き実行履歴 |
| `GET /v1/admin/report-runs/{uuid}` | 状態、各工程、停止/失敗理由、公開 URL |
| `GET /v1/admin/report-schedules` | 定期実行設定一覧 |
| `POST /v1/admin/report-schedules` | 有効なテンプレート/間隔/時刻/params で作成 |
| `PATCH /v1/admin/report-schedules/{uuid}` | enable/disable、検証された設定変更 |

公開記事の閲覧は `/reports/*` の **GET/HEAD のみ**。HTML の本文・一覧は Astro の静的出力であり、私的記事を取得するための新しい無認証 JSON API は必要ない。Quasar に `/admin/reports`（テンプレート選択、実行、状態、スケジュール）と `/reports/` への導線を追加する。`remote_mcp.py` には記事作成ツールを追加しない。将来レポート検索 MCP を追加する場合も明示的に読み取り専用で別途設計する。

## 10. 静的出版と Access 境界

専用 Worker が記事 DB snapshot から Astro 入力を作り、**使い捨ての staging directory** で完全なサイトを静的ビルドする。Node/Astro はこの段階で起動して終了する。HTML/内部リンク/asset hash/禁止タグ/CSP を検査してから、以下の手順で昇格する。

1. 非公開 volume に release 内容を準備し、HTML のみを `releases/<digest>/` に格納。個別原稿、JSON bundle、auth、ログ、構築用ソースを webroot に入れない。
2. fingerprint 付き静的 asset を共有の append-only asset root (`_astro/`) に先に配置する。旧 HTML が参照する asset は一定期間保持する。
3. 既存 `current` への参照を**同一ファイルシステム上で atomic rename** し、全記事一覧・詳細・ナビゲーションを一括切替。DB に昇格済み digest を記録し、DB/ファイルの不一致は起動/公開時に検出・リカバリーする。新規に記事がない場合も空一覧を用意する。
4. 不具合時は直前の正常 release を指すよう rollback。既存のリリースファイルと記事履歴を削除しない。

`nous-mcp` の gateway は別途マウントしたこの volume を**read-only**で提供し、`/reports/`、`/reports/<category>/<slug>/`、`/reports/_astro/<hashed-file>` など**限定されたパスだけ**を処理する。既存 SPA への fallback に巻き込まない。path traversal、拡張子、隠しファイル、シンボリックリンクのルート外脱出を拒否。`access_auth.py` の検証済み JWT と正規 host チェックをそのまま適用し、匿名 ingress/外部配信ドメイン/Access Bypass を追加しない。既存 `/mcp`、`/v1`、`/` の動作を変えない。

Quadlet は `nous-report-worker.container` と記事 volume マウント（Worker: 書込、MCP gateway: 読取）を追加。report worker image は CLI/Node/Astro を固定。`nous-api`、`nous-mcp`、収集 Worker のイメージは不要に肥大化させない。private DB role を用途ごとに分け、バックアップには report テーブル、テンプレート revision、article/asset volume の整合したスナップショットを含める。

## 11. Codex 認証・実行セキュリティ

- インストール管理者が VM 上の専用ユーザー/専用設定領域に**公式 Codex CLI を使って自分でログイン**する。対話不能な SSH/サーバでは製品が案内する device auth 等の正規手段を使用。ChatGPT の Cookie / ブラウザトークンを抜き出さない。
- CLI の認証ストアは**永続 private storage** に置き、権限は専用 UID のみに限定。Access JWT、Nous 管理セッション、Codex 認証情報は相互に転用しない。イメージ・ログ・Git・バックアップに秘密情報を平文で含めない。
- `codex exec` は固定 binary/固定引数でプロセス起動する（shell string 組立て禁止）。作業ディレクトリ、CLI の config、モデル/バージョン、ステージごとの入出力のサイズを制限。モデル利用可能性とサブスクリプションの残量に応じて失敗し、勝手に別 API 課金に切り替えない。
- OS とコンテナで `NoNewPrivileges`、rootless、読取専用 filesystem、限定 temp/workspace、資源上限、タイムアウト、ホスト側の秘密/ネットワークからの分離を強制。Codex 子プロセスには不要な DB 資格情報、Podman ソケット、GitHub token を継承させない。OpenAI 側への必須通信以外の egress は実運用環境で検証・制限する。
- Codex の sandbox/approval 引数は採用バージョンの `codex exec --help` で検証し、**非対話・最小権限**で使用する。認証トークンの更新/失効は運用者が管理。Pi は独立 adapter にしたときのみ追加し、非公式 OAuth 実装を既定にしない。

## 12. 検証と受入条件

| 項目 | 必須の検証証拠 |
| --- | --- |
| モード | スケジュール実行と UI 随時実行が同じ pipeline を利用し、各テンプレートの params が反映される |
| スケジュール/キュー | 二重 tick、同一 slot、worker crash、lease expiry、timeout、retry 上限で二重公開が発生しない |
| 入力・権利 | DB query で上限、時刻、元 `item_version_id`、source policy が維持され、未許諾本文が出力されない |
| 4 工程 | schema に適合する各 stage 成果物が保存され、入力証拠にない主要主張・欠損 ID は fail-closed |
| KEV | `listed`/`not_listed`/`unknown` と `catalog_as_of` が記事で誤解なく表示される。title mention は exploit evidence にならない |
| 出版 | build と検証に成功した場合のみ一括公開。失敗、途中停止、再試行では公開済みサイトを壊さない |
| Access | `/reports/`、asset、記事 URL、管理 POST は未認証では拒否。一般利用者は管理 POST 不可、MCP に書き込み無し、直接 DB 公開無し |
| HTML/UI | XSS/path traversal/危険 URL を拒否。PC・スマートフォン、日本語段落、コード・表、長文、ダークモード、リンクを実ブラウザで確認 |
| セルフホスト | rootless Quadlet が再起動後復帰、Codex 所有者ログインを用いた一件の実記事生成が成功。認証失効や利用上限時は安全に失敗 |
| CI | Alembic upgrade、Python lint/test、Astro build/schema/リンク検査、Quasar typecheck/build、image build。VM 検証と CI は別に報告 |

*最終受入シナリオ*: 管理者が `security-daily` を随時実行 → スナップショットと四工程の記録が残る → 製品の禁止事項を満たす記事を静的 HTML として `/reports/` に公開 → 過去記事・出典・元 CVE を開ける → スケジュール実行でも同じ品質ゲートを通る → 生成失敗時は既存公開内容が変化しない。

## 13. 実装の切り分けとエージェント引継ぎ

**Sol（統括・authority/統合判断）**: この文書、既存の architecture/Access/source-rights と最新 `main` を実装 authority として、受入条件ごとに進捗を管理し、Luna の作業差分・実装境界・テスト結果・CI・VM 動作を検証する。実装者本人の自己検証のみで完成判定しない。独立したレビューを実施するときはその責務を明示する。

**Luna（実装）**: 次の順序で最小変更の独立コミットを積む。SQL/テンプレート/Evidence Bundle → Worker/Codex adapter/四工程 → 検証/記事スキーマ → Astro fixed design/static publisher → Access/Admin/Quasar 導線 → rootless Quadlet/CI/運用文書。レビューなしの `main` 直書きや無関係の既存 UI・取得基盤変更は行わない。

引継ぎ条件: 設計ブランチから実装ブランチを作るか、設計を PR として先に取り込むかは統括が明示する。**本コミットは設計のみ**であり、実装開始、VM への展開、Codex 認証、Cloudflare 設定変更、記事の公開は実施していない。Sol/Luna への実ジョブ起動には利用可能な実行環境・権限が別途必要。

## 14. External references

- OpenAI Codex automation and harness: https://developers.openai.com/blog/codex-as-a-platform ; https://developers.openai.com/blog/eval-skills
- Astro content collections / static output: https://docs.astro.build/en/guides/content-collections/ ; https://docs.astro.build/en/reference/configuration-reference/
- Cloudflare Access self-hosted applications and origin JWT validation: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/

The reference URLs describe upstream capabilities; actual CLI flags, pinned dependencies, licenses, build output, browser behavior and VM connectivity must be verified against the versions selected during implementation.