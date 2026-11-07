# Nous OSINT — Automated Intelligence Reports

Status: **v1 code exists in main; v2 is the authoritative replacement target (NOT YET IMPLEMENTED); owner-authenticated Codex / VM acceptance NOT_CHECKED**
Date: **2026-11-05**  
Authority: [ARCHITECTURE.md](ARCHITECTURE.md), [DATA_MODEL.md](DATA_MODEL.md), [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [REMOTE_MCP_ACCESS.md](REMOTE_MCP_ACCESS.md), [SOURCE_LICENSES.md](SOURCE_LICENSES.md), [CVE_KEV_CORRELATION.md](CVE_KEV_CORRELATION.md)

> **v2実装authority:** [REPORT_PIPELINE_REDESIGN_RFC.md](REPORT_PIPELINE_REDESIGN_RFC.md) と本書を一体の仕様とする。既存の4回Codex呼出しは旧実装の事実であって、今後維持する要件ではない。v2の通常2回実行・検査・公開・診断・管理UIを一つの実装成果として完成させる。v1で公開された記事の互換性、immutable evidence、権限境界、原子的な公開は維持する。本番検証不能を成功扱いしない。

## 1. Goal and decisions

Nous OSINT に、取得済みの公開情報から**利用者向けの品質の高い記事を自動生成し、Cloudflare Access 配下で公開する**機能を追加する。記事生成は既存の収集基盤の代替ではなく、出典付きの派生物である。初期実装は単一 VM のセルフホストを基準とする。

- **利用モード**: (A) スケジュールによる自動実行、(B) UI からの随時実行。テーマ・期間・識別子等は**テンプレートの検証済みパラメータ**として両モードから指定する。任意プロンプト入力・任意 URL 取材は MVP 対象外。
- **編集工程**: 企画・主張候補生成（Codex 1回）→独立事実レビュー（Codex 1回）→決定論的な記事組立・推敲・最終検査→公開。通常2回のみCodexを呼ぶ。修復が必要な場合の追加呼出しは最大2回まで。根拠が不十分なら `skipped` とし、空記事を公開しない。
- **AI ハーネス**: VM 上で所有者が正規に認証した **公式 Codex CLI** の `codex exec` を専用 Worker から非対話実行する。サブスクリプションの認証情報は Nous にコピーしない。モデル・利用上限・利用可能な認証方式は実行時に確認し、保証しない。Pi への差し替えは後続候補であり、初期導入に必要ない。
- **出版**: **Astro の静的 HTML ビルド**を選択する。記事の意味構造だけを Codex に生成させ、デザイン・HTML テンプレート・リンクとコンポーネントは Git 管理の固定実装とする。SSR、常駐 Node サーバ、独立した CMS、メッセージブローカーを追加しない。
- **公開先**: 既存 `https://nous.yohn.jp/reports/` の**同一オリジン・同一 Access アプリケーション**。既存 Quasar は収集 UI・実行管理 UI として維持する。記事は DB と VM 内の private volume に置き、公開 Git リポジトリへ生成記事や原資料をコミットしない。
- **正本**: Git = コード、テンプレート、スキーマ、デザイン。PostgreSQL = 実行設定・ジョブ・記事メタデータ・証跡。専用 volume = HTML ビルド成果物。元 `items` と immutable `item_versions` は変更しない。

### 非目標

公開インターネット向けの記事配信、編集者の承認ワークフロー、ブラウザ WYSIWYG、任意テーマでの自由調査、ソースの利用条件に反する本文転載、推論を観測事実として扱うこと、Codex 認証サービスの再実装、Nous の Quasar を Astro に移植すること、モデル学習・独自エージェントフレームワークの開発は実施しない。

## 2. 既存実装との接続点

初期設計時に `main` (`9414592b7044a475efa954b72c5d2b57e0e2801c`) を調査し、実装は PR #13 および本番イメージの修正 PR #14 で `main` に統合した。

- `src/nous/models.py`: `Source` / `Item` / `ItemVersion` / `CveItemLink`、最新 Alembic `0007`。既存 `fetch_jobs` は取得専用のためレポートジョブと混用しない。
- `src/nous/api.py`: 読み取り専用検索、changes、`GET /v1/cves/{cve_id}`。CVE/KEV の状態は `listed | not_listed | unknown` を厳密に維持する。
- `src/nous/admin.py`: Access subject allowlist と専用 SQL 接続で管理書き込みを提供。レポート実行管理もこの権限境界で提供する。
- `src/nous/access_auth.py`, `remote_gateway.py`: JWT 検証、明示的 HTTP パス・メソッド許可、Quasar の厳密な SPA fallback。`/reports/` と管理 API の追加には**両方の allowlist とルーティング**の更新が必須。MCP は読み取り専用のまま維持する。
- `ui/`: Quasar 2/Vue 3 SPA。ナビゲーションに Reports と生成ジョブ管理を加えるが、記事本体のレンダラーにはしない。
- `deploy/quadlet/`: rootless Podman + PostgreSQL + singleton scheduler/worker + MCP/API/Tunnel。PostgreSQL を外部公開しない。VM に新しい Node/SSR 常駐プロセスを置かない。

## 3. 処理と責務

```text
Approved sources -> PostgreSQL immutable ItemVersion
                        |
         read-only bounded evidence snapshot (SHA-256, source policy)
                        |
             report_runs durable SQL queue (manual/scheduled)
                        |
                 Report Worker (rootless)
                   - Codex auth/model/UID readiness and diagnostics
                   - Call #1: editorial proposal + evidence-linked claims
                   - Call #2: independent claim review
                   - Optional bounded repair / re-review (+2 calls maximum)
                   - Deterministic article-v2 assembly and quality gates
                        |
              Astro static build + HTML/links/assets check
                        |
                Atomic release promotion (old site preserved on failure)
                        |
          Access-protected /reports/* and Admin run diagnostics
```

Report Worker は既存収集Workerと別イメージ・Quadlet・DB secretで稼働する。公式Codex CLIは固定引数・同一の非特権UID/GID/認証ホームで実行し、認証情報・非許諾本文・DB資格情報をモデルやjournaldへ漏らさない。Pythonがキュー・モデル呼出し・検査を統括し、Node/Astroは公開ビルド時の使い捨てプロセスとしてのみ起動する。

単一Worker（同時生成1件）とSQL lease、idempotency、retry fenceは維持する。各試行のstage・exit status・安全なJSONL・timing・error codeを追跡可能にし、失敗したstageから同一immutable snapshotで再開する。実装範囲と完全な受入条件はv2 RFCを参照する。

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

## 6. 編集工程と品質ゲート（v2）

| Stage | 実行主体 | 入力/出力 | 合否と復旧 |
| --- | --- | --- | --- |
| Evidence selection | 決定論的処理 | DB snapshot → bounded evidence view + SHA-256 | 元版・権利・日時を検証。根拠不足は skipped |
| Candidate claims / 企画・執筆 | Codex call #1 | topic, claim_id/text/classification/evidence_ids, section | 根拠ID不整合を拒否。掲載価値なしは skipped |
| Independent review / 事実検証 | Codex call #2 + gate | claimごとの accepted/rejected/needs_revision | 独立判定と機械的な証拠・KEV・利用条件検査 |
| Bounded repair | 必要時のみCodex | 指摘されたclaimだけ修正→再レビュー | 最大追加2回。修正不能なら未公開 |
| Article assembly / 推敲 | 決定論的処理 | 承認claim → article-v2（固定見出し/出典） | 意味を新規生成せず重複/並び/表示を整える |
| Publication | 決定論的処理 | schema/rights/security gate → Astro → atomic promotion | 実際のHTML/asset検査に合格しなければ現行releaseを維持 |

モデルには根拠付きの原子的主張と独立レビューだけを生成させ、HTML・URL・publisher metadata・KEV状態や任意の追加取材は生成させない。四つの編集責務を保持するが**四つの独立したモデル呼出しは仕様としない**。モデルの自己申告のみで真実性を保証したことにしない。

最終ゲートは、canonical JSON schema、claim/evidence/immutable version対応、観測/推論/未確認の区分、CVE/KEV三値・鮮度、引用権利、入力期間、数値・禁止文、未承認HTML/JS/URL、出典一覧、Astro内部リンク/assetを検査する。許諾外の情報が必要な主張は除外し、裏付けできない場合は公開せず理由を記録する。失敗理由は run_id、attempt、failed_stage、終了ステータス、診断参照を持つイベント履歴に残す。

## 7. 記事スキーマと固定デザイン

新規生成の正本は `reports/schemas/` で管理する **candidate/review/article-v2** 契約とする。Codexには浅いJSON構造（claim_id、text、classification、evidence_ids、承認/却下/差戻し）だけを要求し、モデル出力JSONとlocal canonical validationを分離する。記事本文は採用済みclaimを一切意味変更せず決定論的に組み立て、タイトルはテンプレート名・日付・正規CVE ID等の中立的なDB由来メタデータから構築する。新規の根拠・推論・出典URLをレンダラーが補完しない。

既刊 `article-v1.schema.json` のJSONと記事URLは変更・再生成しない。Astroの読み込み/レンダリングを **v1/v2両方**に対応させる。v2だけを新規生成に利用し、旧4回の生成モードを残す必要はない。

固定コンポーネントは既存 `paragraph`, `bullet_list`, `fact_table`, `source_list`, `cve_fact`, `quote` のうち証拠・権利条件を満たすものを利用する。デザイン、HTML、CSS、リンク/Access、公開slug、noindex、static buildをCodexの自由生成に委ねない。

公開URLは既存の `/reports/` と `/reports/{category}/{slug}/` を維持し、既刊との衝突を禁止する。

## 8. 永続化とジョブ契約

既存 `fetch_jobs` を変更せず、Alembic **0008**（既存 `0007` の後続）で新規モデルを追加する。想定テーブルは以下。列名・型は実装で最小限に整合させるが、**一意性と監査要件は変更しない**。

| テーブル | 正本として保持する内容 | 主な不変条件 |
| --- | --- | --- |
| `report_schedules` | template/revision、検証済み params、タイムゾーン、cadence、次回予定、enabled、作成 actor | next slot を UTC で確定。過去 slot を無制限 catch-up しない |
| `report_runs` | UUID、trigger、template/revision、params、schedule slot、idempotency key、state、lease/attempt、入力 cutoff/hash、stage、failed_stage、error code、timestamps、生成 report_id | 同一 schedule + slot は一度だけ投入。失敗工程と状態は分離し、lease fencingを維持 |
| `report_run_events`（v2） | run_id、attempt、seq、timestamp、stage、event_type、error_code、exit_status、duration、usage、artifact hash、safe diagnostic reference | append-only。管理者だけ参照可能で、認証情報・生prompt・未加工stderrを含めない |
| `reports` | UUID、unique slug、article schema version、元 run ID、headline、要約、カテゴリ、published_at、artifact digest/path、supersedes ID、生成モデル/ハーネス version、input digest | 既刊データは不変。修正/再刊は新 UUID + supersedes。失敗時は既刊を維持 |
| `report_evidence` | report ID、evidence ID、item ID + **item_version ID**、source URL、観測日時、relation、出典種別 | 必ず元データの immutable version に解決し、関係を偽装しない |

静的 HTML サイトは最大 1,000 件の既存公開記事を一括ビルドする。上限に達した場合、新規記事の生成ジョブは `report_archive_limit_exceeded` で失敗し、既存の公開ポインタ・既存記事を変更しない。DB 上の記事を無断削除して解消しない。保持・ページ分割に関する仕様変更は独立して決定する。

中間生成物（v2: `candidate_claims`, `claim_review`, `article-v2`、必要時のrepair）と検査・診断ログは非公開のジョブ領域に保存する。v1の既存履歴は互換性のため参照可能にする。実行履歴のメタデータと最終 immutable 記事は DB に永続化し、ファイルを消しても再ビルド可能にする。巨大な raw bundle は private artifact volume に hash 付きで保存して参照し、DB にその hash と保管期限を保持する。記事への掲載が許されない本文は永続的に転載しない。

ジョブ状態: `queued → leased/running → validating → publishing → published`、終端は `skipped`, `failed`, `cancelled`。`failed_stage` と append-only events は `state` から独立して保存する。一時的なネットワーク障害のみステージ単位の有限再試行を許可し、auth/モデル権限/不正schema/権利違反は無条件再試行しない。lease heartbeat・途中停止時cleanup・重複刊行防止を保持。認証情報はjournaldと通常diagnosticsに残さず、redacted/private diagnosticsには保存上限・保持期間を設ける。

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

**表示テンプレートの更新:** Worker image の Astro `src/`・`public/`・設定・ロックファイルから renderer fingerprint を算出し、リリースの非公開 manifest に記録する。Worker の定期的な整合性確認では、active release が正しく存在していても renderer fingerprint が異なれば、保存済み記事 JSON 全件から静的サイトを再構築する。既存と同じ publication lock、HTML/アセット/リンク検査、content digest、atomic pointer、DB 状態更新を再利用する。記事自体の再生成、版・run・source 記録の変更、Access 経路追加は行わない。古い image へ戻す場合もその image の renderer に戻せる。HTML を差し替えるには新しい report Worker **image のVMへの適用**が必要であり、Quasar frontend deployment では変更されない。実行後は `report_site_state.active_digest`、`current` link、非公開 manifest の fingerprint、記事表示と旧リリース保全を検証する。

`nous-mcp` の gateway は別途マウントしたこの volume を**read-only**で提供し、`/reports/`、`/reports/<category>/<slug>/`、`/reports/_astro/<hashed-file>` など**限定されたパスだけ**を処理する。既存 SPA への fallback に巻き込まない。path traversal、拡張子、隠しファイル、シンボリックリンクのルート外脱出を拒否。`access_auth.py` の検証済み JWT と正規 host チェックをそのまま適用し、匿名 ingress/外部配信ドメイン/Access Bypass を追加しない。既存 `/mcp`、`/v1`、`/` の動作を変えない。

Quadlet は `nous-report-worker.container` と記事 volume マウント（Worker: 書込、MCP gateway: 読取）を追加。report worker image は CLI/Node/Astro を固定。`nous-api`、`nous-mcp`、収集 Worker のイメージは不要に肥大化させない。private DB role を用途ごとに分け、バックアップには report テーブル、テンプレート revision、article/asset volume の整合したスナップショットを含める。

実装では `Containerfile.reports` を API/MCP/collection image から分離し、公式 `@openai/codex` CLI `0.166.0` と Node 24/Astro 依存を固定する。Worker のみが専用 DB URL secret を受け取り、rootless volume と read-only root filesystem を使う。Codex 子プロセスは UID/GID 10002 に落とし、認証状態は専用 private volume に置く。記事 volume は MCP から read-only mount する。Worker は HTTP listener や Podman socket を持たない。

バックアップ時は report Worker を停止し、PostgreSQL の exported repeatable-read snapshot と volume archive を取得する。DB の `report_site_state.active_digest`、`current` symlink、active manifest、HTML と asset の hash を一致確認し、不整合時は中断する。暗号化された tar artifact と counts/checksum manifest の両方を保管し、restore check は隔離 PostgreSQL と使い捨て volume に復元して schema/data と active site digest/assets を確認する。DB と filesystem の kernel-level atomic snapshot ではないため、この停止と照合を必須とする。

## 11. Codex 認証・実行セキュリティ

- インストール管理者が VM 上の専用ユーザー/専用設定領域に**公式 Codex CLI を使って自分でログイン**する。対話不能な SSH/サーバでは製品が案内する device auth 等の正規手段を使用。ChatGPT の Cookie / ブラウザトークンを抜き出さない。
- CLI は検証済みの公式 `@openai/codex` npm package `0.166.0` を report Worker image に固定する。CLI の認証ストアは**永続 private storage** に置き、権限は専用 UID/GID 10002 のみに限定。Access JWT、Nous 管理セッション、Codex 認証情報は相互に転用しない。イメージ・ログ・Git・バックアップに秘密情報を平文で含めない。
- `codex exec` は固定 binary/固定引数でプロセス起動する（shell string 組立て禁止）。作業ディレクトリ、CLI の config、モデル/バージョン、ステージごとの入出力のサイズを制限。モデル利用可能性とサブスクリプションの残量に応じて失敗し、勝手に別 API 課金に切り替えない。
- OS とコンテナで `NoNewPrivileges`、rootless、読取専用 filesystem、限定 temp/workspace、資源上限、タイムアウト、ホスト側の秘密/ネットワークからの分離を強制。Codex 子プロセスには不要な DB 資格情報、Podman ソケット、GitHub token を継承させない。OpenAI 側への必須通信以外の egress は実運用環境で検証・制限する。
- Codex の sandbox/approval 引数は採用バージョンの `codex exec --help` で検証し、**非対話・最小権限**で使用する。認証トークンの更新/失効は運用者が管理。Pi は独立 adapter にしたときのみ追加し、非公式 OAuth 実装を既定にしない。

## 12. 検証と受入条件

| 項目 | 必須の検証証拠 |
| --- | --- |
| モード | スケジュール実行と UI 随時実行が同じ pipeline を利用し、各テンプレートの params が反映される |
| スケジュール/キュー | 二重 tick、同一 slot、worker crash、lease expiry、timeout、retry 上限で二重公開が発生しない |
| 入力・権利 | DB query で上限、時刻、元 `item_version_id`、source policy が維持され、未許諾本文が出力されない |
| v2編集工程 | 通常Codex 2回、必要時の修正・再レビューを含め最大4回。claim生成・独立review・決定論的記事組立がschemaに適合し、未裏付け主張・欠損IDはfail-closed | 
| 障害診断 | run_id/attempt/failed_stage/exit status/JSONL/安全なstderr分類が管理者向け履歴と非公開診断に保存され、無用な再試行をしない |
| KEV | `listed`/`not_listed`/`unknown` と `catalog_as_of` が記事で誤解なく表示される。title mention は exploit evidence にならない |
| 出版 | build と検証に成功した場合のみ一括公開。失敗、途中停止、再試行では公開済みサイトを壊さない |
| Access | `/reports/`、asset、記事 URL、管理 POST は未認証では拒否。一般利用者は管理 POST 不可、MCP に書き込み無し、直接 DB 公開無し |
| HTML/UI | XSS/path traversal/危険 URL を拒否。PC・スマートフォン、日本語段落、コード・表、長文、ダークモード、リンクを実ブラウザで確認 |
| セルフホスト | rootless Quadlet が再起動後復帰、Codex 所有者ログインを用いた一件の実記事生成が成功。認証失効や利用上限時は安全に失敗 |
| backup/restore | Worker 停止中の DB/site capture、active digest・manifest・HTML/asset hash の一致、隔離 restore 後の schema/count/digest/assets 検証 |
| CI | Alembic upgrade、Python lint/test、Astro build/schema/リンク検査、Quasar typecheck/build、API/Worker image build。VM 検証と CI は別に報告 |

Fixture pipeline と CI はオーナー認証済み Codex 実行や VM acceptance の証拠ではない。実施前の状態は明示的に **NOT_CHECKED** と報告する。

*最終受入シナリオ*: 管理者が `security-daily` と `cve-kev-deep-dive` を実行 → evidence snapshot、Codexのclaim生成・独立review、決定論的article-v2生成、検査・静的HTML公開までが一連で成功 → Access経由で記事・既刊v1・出典を閲覧できる → スケジュールでも同じv2経路が動作 → 故障時はfailed_stageと診断情報が確認でき、既存公開内容が変化しない。実機未検証はNOT_CHECKEDと記す。

## 13. 実装の切り分けとエージェント引継ぎ

**実装 authority**: この文書、ARCHITECTURE / DATA_MODEL / SOURCE_LICENSES / ACCESS と `main` の既存コード・テストを照合する。後続変更は CONTRIBUTING.md に従い専用ブランチと PR で審査し、CI と VM 動作を別々に報告する。

既存v1実装は `main` に統合済みだが、**本書のv2置換実装は未完了**。Codex/DB/記事スキーマ/レンダラー/管理UI/実行診断を統合して一つの完成成果として提供する。旧4回方式を維持するための中間PR/切替feature flagは不要。**GitHub Actions での検証は VM への展開・起動成功の証拠ではない**。オーナー認証済み Codex による実記事生成、VM での Report Worker / HTML 配信、Cloudflare Access を通した受入確認は **NOT_CHECKED** として扱い、実行後の観測結果でのみ更新する。fixture pipeline/CI の結果を実環境受入と混同しない。

## 14. External references

- OpenAI Codex automation and harness: https://developers.openai.com/blog/codex-as-a-platform ; https://developers.openai.com/blog/eval-skills
- Astro content collections / static output: https://docs.astro.build/en/guides/content-collections/ ; https://docs.astro.build/en/reference/configuration-reference/
- Cloudflare Access self-hosted applications and origin JWT validation: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/

The reference URLs describe upstream capabilities. The selected Codex package is `@openai/codex@0.166.0` and its image build checks `codex-cli 0.166.0`; fixture CI and actual owner-authenticated VM operation remain separate evidence.
