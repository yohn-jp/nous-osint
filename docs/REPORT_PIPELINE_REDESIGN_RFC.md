# RFC — Nous OSINT レポート生成パイプライン v2

Status: **PROPOSED / NOT IMPLEMENTED**  
Date: 2026-11-07  
Reviewed baseline: main **8acb56e5f0a8230c66cd1b34a70d714be9125702**  
Scope: report generation, Codex invocation, failure diagnostics, recovery, report-admin observability. Source ingestion, Cloudflare routing, MCP authorization, report-site release atomicity are unchanged.

## 0. 目的と非目標

対象は、所有者認証済みの公式 Codex CLI と既存 PostgreSQL / rootless Podman Report Worker / Astro static renderer を利用する自動記事生成。**まず失敗を特定できること、次に有効な記事を安定して生成できること**を完了条件とする。成功を偽装するための validator 無効化、無根拠な記事、無断取材、API キー課金への無断切替、認証情報のコード・ログへの混入、VM 上の別 CMS/常駐 Node サーバ追加は禁止。

既存の [AUTOMATED_INTELLIGENCE_REPORTS.md](AUTOMATED_INTELLIGENCE_REPORTS.md) にある「企画、事実検証、執筆、推敲」の**編集責務**、出典・権利管理、公開の fail-closed と immutable evidence は維持する。ただし、各責務を毎回別々の汎用 LLM 呼び出しとして実装する指定は本 RFC で見直しを提案する。**本 RFC は設計方針として採用する。採用と本番実行切替は別操作とする。** PR #38マージ時点では現行の4回Codex実行・既存記事契約・受入条件を維持する。v2の2回実行は実装・統合・実機受入が完了するまで有効化しない。既存文書にはこの段階移行条件を採用時に追記し、正式切替時に4回実行の規定と受入条件をv2へ更新する。

## 1. 現在の実装から確認できた障害増幅要因

| 箇所 | 観測したコード上の事実 | 結果 |
| --- | --- | --- |
| src/nous/report_pipeline.py:859–892 | 同じ evidence bundle を plan → fact_check → draft → edit の Codex **4回**に再投入 | 4回の起動・認証・モデル応答のいずれかが失敗すると未公開 |
| src/nous/report_pipeline.py:551–558, 368–550 | title、dek、summary、表示本文、fact_check claim の**文字列完全一致**を要求 | 推敲は実質改稿できず、通常の日本語文章生成に不自然な制約がある |
| src/nous/report_pipeline.py:859–892 | fact_check の revision_request は保存されるが分岐に利用されない | 差し戻しが実装されず、修復より失敗が優先される |
| src/nous/report_pipeline.py:770–856 | Codex stdout/stderr を一時ファイルに保存し、stderr末尾から分類した後に破棄。--json なし | 途中の JSONL イベント、失敗理由の詳細、モデル使用量、転送状態を追跡不能 |
| src/nous/report_pipeline.py:851–857 | 子プロセス警告には stage と exit_status はあるが run_id/attempt がない | 同時期の失敗と report_runs の対応が難しい |
| src/nous/report_worker.py:307–327 | 失敗時に report_runs.stage を failed / retry_wait に上書き | 故障した工程と進捗が UI・DB 上から消える |
| src/nous/report_worker.py:832–894 | 完了時・失敗時の作業ディレクトリを削除。再試行は先頭工程から実行 | 調査素材と既に成功したモデル出力を活用しづらい |
| reports/schemas/article-v1.schema.json | モデルに長大な block union/claim/evidence スキーマを直接生成させる | schema/形式/本文の複雑な整合性がモデル呼び出しの成功率を左右する |
| Containerfile.reports、deploy/quadlet/nous-report-worker.container | Codex 0.166.0、UID/GID 10002、read-only、Podman ボリュームを固定 | 実際のバージョン、認証、書込権限、CA/proxy、モデル利用可否は VM 実測が必要 |

上記は**実装から確定できる構造上の問題**であり、現場で発生中の codex_execution_failed の根本原因を特定したものではない。VM のオーナー認証を伴う end-to-end 実行は未検証。

## 2. 推奨パイプライン

~~~text
ReportRun (manual / scheduled) -- SQL queue + lease fencing
    |
    +-- 0. Readiness check: CLI / auth / permitted model / filesystem / egress
    |       failure => blocked/config-error; never attempt article generation
    |
    +-- 1. Evidence snapshot (deterministic, unchanged authority)
    |       - exact time cutoff, immutable ItemVersion and license constraints
    |       - dedup/rank/select relevant evidence up to bounded prompt budget
    |       - insufficient material => skipped with explicit reason
    |
    +-- 2. Editorial proposal + atomic claims (Codex call #1)
    |       - select thesis/topic, generate concise, source-linked candidate claims
    |       - every claim has ID, evidence IDs, classification and intended section
    |
    +-- 3. Independent fact review (Codex call #2 + deterministic rules)
    |       - accept / reject / revise for each claim
    |       - semantic grounding against provided allowed metadata
    |       - ensure no newly fabricated CVE/KEV/exploitation facts
    |       - reject/drop unsupported claims
    |       - optional single bounded repair + re-review (at most +2 calls)
    |
    +-- 4. Deterministic editorial assembly (no Codex call)
    |       - approved claims -> article-v2 data model
    |       - fixed/parameterized headings, chronological grouping, sources
    |       - deterministic title/summary only from neutral metadata and
    |         previously approved claim text
    |       - independent final schema/provenance/rights/security gate
    |
    +-- 5. Existing Astro static build and atomic publication
            - immutable report + evidence relations, artifact hash
            - promote only when SQL lease and release checks succeed
            - old public report stays unchanged on every failure
~~~

4つの編集責務を **企画・主張生成（call #1）、独立検証（call #2）、決定論的な編集・表示組立** に再配置する。通常は2モデル呼び出し、根拠付きの修正が必要な場合でも最大4回。企画が必要なのは文章を増やすためではなく掲載価値の判定である。雑多な200件を毎回全投入せず、既存 evidence を維持したままモデル向け view を小さく選別する。選別・除外理由を記録し、情報量の多い場合も恣意的に事実を書き換えない。

### 2.1 Evidence と記事品質の境界

- 既存 bundle は正本として SHA-256 固定。生成用 view は whitelist フィールド・許諾範囲内のタイトル、日時、publisher URL、根拠グレードのみを使い、ハッシュと選別条件を保存する。公開記事は常に元の immutable version に再解決できる。
- 情報がタイトル等の metadata のみなら「当該 publisher にそのタイトルの掲載が観測された」と述べられる。**記事本文を確認した、原因や影響が裏付けられた、と推測で補わない。**
- CVE の exact match、KEV の listed / not_listed / unknown、鮮度、権利、観測期間は既存の決定論的 read model を正本とする。LLM に CVE/KEV 状態を判定させない。
- 情報源が古い・少ない・内容を確証できない場合は **skipped(reason=insufficient_evidence)** とし、「生成失敗」と区別。公開済みレポートを空記事で置換しない。
- 重要度や本文の長さは入力の根拠量に比例。固定の字数を埋めるための創作文は禁止。

### 2.2 Codex 生成物を最小化する

Call #1 の構造化出力案:

~~~json
{
  "decision": "publish",
  "theme": "当日確認された公開アドバイザリの更新",
  "claims": [
    {
      "claim_id": "C001",
      "text": "E001の公表元が更新通知を公開したことを観測した。",
      "classification": "observed",
      "evidence_ids": ["E001"],
      "section": "primary_observations",
      "importance": "normal"
    }
  ]
}
~~~

Call #2 は claim_id をキーに **accepted / rejected / needs_revision**、根拠ID、判断理由コードだけを返す。新しい事実や新しい evidence は提案しても自動採用しない。accept した主張の text と evidence_ids は immutable とし、記事構築時に文字列再生成をしない。reviewer が accepted にしても、決定論的な要件（根拠ID・期間・ライセンス・CVE/KEV・禁止文・数値など）を満たさないものは拒否。モデルだけで外部事実の真偽を証明した扱いにしない。

新しい generation schema は **浅い object / array / enum** を主体とし、provider に渡せない制約を削った派生スキーマを使う。厳格な検証はローカル canonical schema + cross-reference gate に分離。provider に article-v1 の大きな複数種 block union や publisher metadata の生成を求めない。

### 2.3 公開データの構成

モデルが書くのは原子的主張まで。記事の title は「テンプレート名 / 対象日 / exact CVE ID」等の**中立メタデータ**で決定論的に構成する。dek/summary/sections は承認済みの claim を正本として選択・配置し、推測を補う自由文を挿入しない。出典一覧、publisher URL、最終観測時刻、KEV panel、未確認表記は DB から生成する。ブロック HTML と styling は既存 Astro 正本のまま。

article-v1 は title、dek、summary に「同一 claim text の完全一致」を要求するため、v2 では schema_version=2 の新しい表示契約を定義する必要がある。**過去に公開された v1 記事を上書き/変換せず**、Astro に v1/v2 双方を読み取る adapter を追加する。公開済み記事・digest・slug の不変条件は保持する。v2 article は review 済み claim テキストの参照と編集上の配列・見出しを表現し、検証が全て通るまで公開しない。

## 3. Codex 実行基盤契約

1. **同一 identity / 同一 CODEX_HOME**: startup preflight、CLI --version、認証確認と実行を、実際に使用する UID/GID=10002・同じ volume・同じ network namespace で行う。コンテナ root の成功をもって子プロセス成功としない。owner は公式 login --device-auth 等で認証し、OAuth token の横流し・独自再実装を禁止。
2. **model 明示**: 現行 --ignore-user-config により利用者の config.toml を読まない。サービス側でモデルを明示選択・固定し、そのモデルがオーナー認証で利用できることを最小の schema smoke で確認する。モデルの silent fallback、API課金切替は不可。
3. **実行コマンド**: 安定版 CLI の実際の --help / --version を検査し、固定引数で codex exec --json --ephemeral --ignore-user-config --skip-git-repo-check --sandbox read-only --output-schema schema.json --output-last-message output.json - を呼ぶ。prompt は stdin。version やオプションを未検証で推測変更しない。
4. **実行環境**: 権限分離、不要な環境変数・DB secret・Podman socket の隔離、許容通信と CA/proxy の明示、作業領域の使用可能容量・所有者/パーミッションを preflight で確認。read-only sandbox **だけ**では OS ファイル読取を完全に隔離できないので、子プロセス可視 mount / egress も点検する。
5. **失敗伝達**: 子プロセスの exit status と --json の turn.failed/error、output 最終ファイル、期限、セッション通信状態を別々に検査。stdout か JSON が欠損していても、診断情報を保存してから故障コードを返す。
6. **運用可用性**: readiness は実行時にも TTL で再確認。auth/config/model 不可なら新規ジョブを「原因付き waiting/blocking」として保留し、無意味に attempts を使わない。モデルを呼ぶ smoke は新イメージ/認証変更時と明示的オンデマンド時に限定して濫用しない。

Codex 公式 CLI は --json で thread.started、turn.started、turn.completed、turn.failed、item.*、error、token usage を提供する。--output-schema、--output-last-message と併用できる。read-only / ephemeral / stdin は公式オプションである。ただし **採用バージョン 0.166.0 の本番環境で必ず互換性検証する**。

## 4. 診断を失わないログ設計

### 4.1 正本・ログの分離

- PostgreSQL: report_runs の状態正本を維持し、新しい append-only **report_run_events**（run_id, attempt, seq, timestamp, stage, event_type, error_code, exit_status, elapsed_ms, usage, artifact_sha256, diagnostic_ref）を Migration 0011 で追加。失敗 stage は report_runs.failed_stage として state とは別保存。既存 stage を failed/retry_wait で上書きしても過去の工程が消えない。
- 非公開ボリューム: runs/<uuid>/attempts/<n>/<stage>/ 以下に **入出力 SHA-256 / CLI version / redacted JSONL events / bounded redacted stderr / command manifest** を atomic write / fsync。mode 0700 ディレクトリ / 0600 ファイル。CLI認証 cache と診断ファイルは別 volume/permission。
- journald: run_id、attempt、stage、event_type、error_code、exit_status、elapsed_ms、diagnostic_ref、safe summary のみ。secret、Bearer、auth.json、任意 prompt、出典全文、PII、フル exception dump を書かない。
- 管理API/UI: 既存 Access subject allowlist で管理者だけに bounded stage history を提供。stage、開始/終了、失敗分類、retryable、次回予定、elapsed、使用量、診断参照を表示。デフォルトで生ログ全文・token・prompt は返さない。

### 4.2 イベントサンプル

~~~json
{
  "event": "codex_stage_failed",
  "run_id": "00000000-0000-0000-0000-000000000000",
  "attempt": 1,
  "stage": "claim_review",
  "cli_version": "0.166.0",
  "model": "explicitly-configured-model",
  "exit_status": 1,
  "error_code": "codex_auth",
  "duration_ms": 1354,
  "stdout_bytes": 542,
  "stderr_bytes": 1314,
  "jsonl_last_event": "turn.failed",
  "diagnostic_ref": "runs/.../attempts/1/claim_review/diagnostic.json"
}
~~~

stdout JSONL はイベント型・phase・usage・失敗型などの **allowlist fields だけを抽出**して記録する。agent message、reasoning、tool command、未加工 error text をそのまま管理 API や journal に転送しない。詳細 stderr はトークン/認証ヘッダ/URL query などを除去した bounded preview のみ通常保存。調査上どうしても raw が必要なら、明示的な一回限りの owner-only debug mode で private volume に短期（例: 24h）保存し、暗号化ストレージ・アクセス監査・上限・自動消去を必要条件とする。raw の常時保存は採用しない。

診断保存に失敗したら公開判断とは独立した code=diagnostic_persist_failed を管理イベントに残し、CI fixture で再現可能にする。正常終了時は成功イベントと最終出力 digest を保存。標準保持案: metadata 90日 / redacted diagnostics 14日 / owner raw debug 24時間。保持期間は固定の設定値で一括管理し、publish した article/evidence の永続保存と混同しない。

## 5. 失敗分類・再試行・resume

| 種別 | 例 | 対応 |
| --- | --- | --- |
| environment / config | codex binary/flag/version、UID、sandbox、読み書き、schema rejected | **no retry**。blocking に分類し修正後の再実行を待つ |
| auth / entitlement | 未認証、token期限、権限不足、利用限度・quota | **no automatic retry**。オーナー対応または quota reset を待つ。認証情報をログに書かない |
| transient | 一時的 network/5xx、接続断、確定した一過性 timeout | 同一 stage/input/model で bounded retry（最大2、指数 backoff + jitter、可能なら Retry-After 尊重） |
| content / validation | Unsupported claim、schema-invalid content、evidence mismatch | 不適切な claim を拒否・除外。必要なら **1回のみ**根拠を示して修正し、再レビュー。失敗なら failed_validation |
| no article warranted | evidenceなし / 裏付けclaimなし | skipped + reason。空記事を公開しない |
| lease / publication | lease lost、build failure、DB/site pointer mismatch | 既存 fencing/atomicity を維持。安全な時点から再実行、旧サイト保持 |

**再試行は「run 全体」ではなく失敗した stage 単位**。各 stage artifact は SHA-256(input + schema_revision + prompt_revision + model + output) で検証可能とし、再取得・再実行でも同じ observed_cutoff / template snapshot を維持。stage の成果物を private volume に atomic write/fync **してから** DB 上に digest+完成をコミットする。DB だけ完成扱いでファイルがない矛盾を作らず、残った孤児ファイルは復旧時に照合/掃除する。違う入力や generator revision では既存 stage output を再利用しない。

重複スケジュール投入、concurrent claim、期限切れ lease 回収、publish 二重実行の既存一意制約と fence は継続。モデルの非決定性を理解し、**過去の承認済み出力の再利用**は同一 SHA と immutable 内容の検証に限る。古い published report は修正/破棄せず、新しい run と supersedes 管理にする。

## 6. 実装差分と権限境界

- src/nous/report_pipeline.py: CodexRunner を **preflight + invoke + JSONL parser + output gate** に分解。生成は candidates/review の小さな schema。current article-v1 validator は legacy 用に残し、新規 article-v2 の projectors と validator を追加。
- src/nous/report_worker.py: stage transitions と report_run_events を transactionally 記録、失敗 stage を保持。run の resume、artifact-digest、分類別 retry。既存 _publish_candidate、atomic release/pointer、evidence DB validation を再実装しない。
- src/nous/models.py + migrations/versions/0011_*: 最小限の append-only events / failed_stage 等の追加。既存 Job/Report/ReportEvidence 正本は維持。既存 DB ロールへ必要最小の DML 権限を追加。
- src/nous/admin.py, UI AdminReportsPage.vue: 管理者限定 stage timeline と具体的な対処可能 code・日付/試行番号。任意ファイルパスを受けるログダウンロード API や任意 shell 実行 API は作らない。
- reports/schemas/, reports/site/: candidate/review/article-v2 の schema と v1/v2 共存。見出しと文字列をモデル自由生成させず、既存 Astro component/style を再利用。
- Containerfile.reports, Quadlet: CLI version/OS/network/UIDの所有権を実機で確認。認証 cache を更新/消去せず、起動前 preflight を実行。画像 digest 固定と所有者認証は維持。

## 7. 段階的導入（責務が独立した3 PR）

**PR A — 可観測性 / 実際の障害特定（最優先）。** 実行挙動は4 stagesのまま、--json、run_id付きイベント、stderr安全保存、failed_stage、コマンド/バージョン/認証 readiness、失敗コード改善を追加する。既存 Codex CLI の正常1回と失敗1回を**VMで実測**し、現在の codex_execution_failed の真因を確定して最小修正する。PR A 自体ではモデル用 schema や記事文を改変しない。

**PR B — 編集工程の簡素化。** 2 calls + deterministic assembly、独立 reviewer、bounded revision、article-v2 と v1 互換 renderer、input artifact、stage resume を追加。原文・ライセンス・CVEの安全要件は維持。旧実行データに v2 の新しい制約を遡及適用しない。feature flag で旧系から段階的に切り替える。

**PR C — 管理/UI と受入。** Stage timeline、対処別エラー、明示的な修正後再実行、運用メトリクスを追加。レポート本文の実機閲覧・端末別表示・Access認可・負荷・ロールバックを確認。設計採用時に追記した移行条件に従い、実機受入が成功してv2を正式有効化する際に、元の AUTOMATED_INTELLIGENCE_REPORTS.md の4-stage/CLI call定義と受入条件をv2へ改訂する。旧系を削除するのは確認後だけ。

各 PR は CONTRIBUTING.md に従い別ブランチ/レビューとし、DB migration と本番更新は別の操作として扱う。不要なフロントエンド/Cloudflare/収集系変更を混ぜない。

## 8. 受入条件（完了の判定証拠）

1. 実際の Worker UID/GID、CODEX_HOME、Codex version、モデル、TLS/ネットワーク条件で owner-authenticated **最小1回成功**。API key への勝手な切替なし。
2. 同じ環境で security-daily と CVE/KEV の **記事をそれぞれ1件実生成**し、HTML を Access 認証済みで閲覧できる。fixture 成功だけでは不可。
3. レポート1件につき通常モデル呼び出し2回、修正時の上限4回。モデル出力 JSON と最終 article が schema/根拠/権利に合致。
4. 任意の Codex 失敗を起こすと、run_id、attempt、failed_stage、エラー分類、exit status、所要時間、JSONL event、診断参照が DB/UI から対応付く。
5. 認証失効、禁止モデル、schema不一致、network timeout、資源不足、output invalid、CLI exit!=0 が**別の分類**で記録され、再試行ポリシーが一致。
6. ログには auth token、Bearer、Cookie、認証 JSON、原文全文など秘密情報がなく、private diagnostic file だけが所定期間残る。異常時も trace が失われない。
7. 4段階の編集責務に相当する計画、主張、レビュー、編集・検査の成果物が inspectable で、revision_request が実際の bounded repair に結びつく。
8. 無根拠主張、曖昧な exploit/KEV 状態、未許可引用、出典ID不整合、架空 URL は deterministic gate で拒否。
9. evidence 不足や修正不能は skipped/failed に正しく分岐。成功の偽装、空記事、後続工程の無条件実行を禁止。
10. transient retry は同一 snapshot と stage artifact を保持。crash・lease reclaimed・DB retry・Astro build失敗でも二重公開せず、既存記事に変更なし。
11. 管理API/UI の error diagnostics は owner 管理者だけに公開し、一般利用者/MCP から到達不能。
12. CI: Python/DB migrations、fixture pipeline、Codex JSONL parser、safe log/redaction、schema/quality gates、Astro v1/v2 build、lease/recovery。CI green と本番実行は別報告。
13. VM: rootless Podman Quadlet restart、正しい GHCR digest の稼働、秘密 volume 権限、ログ rotation、容量超過復旧を観測。
14. ロールバック時に v1 pipeline・現行 Astro/Report DB・過去公開 digest を復元できる。DB/schema互換の復旧経路を検証し、無断削除しない。

## 9. 公式仕様と参照

- Codex non-interactive、--json events、--output-schema と --output-last-message:
  https://learn.chatgpt.com/docs/non-interactive-mode
- Codex exec の sandbox、--ephemeral、--ignore-user-config、stdin、
  JSONL/CLIフラグ: https://learn.chatgpt.com/docs/cli/reference
- Codex auth, CODEX_HOME, device auth and custom CA:
  https://learn.chatgpt.com/docs/auth
- OpenAI Structured Outputs JSON Schema のサポート範囲:
  https://developers.openai.com/api/docs/guides/structured-outputs

**設計上の現況:** GitHub の main と公式 CLI ドキュメントから確認。VMの実行ログ・オーナー認証・CLI利用可能モデル・本番記事生成は未確認。PR A の本番診断によって、実際の codex_execution_failed の原因を確定する。
