# Nous OSINT

公開情報を継続的に収集し、出典と変更履歴を保持したうえで検索・分析できる、汎用OSINT基盤。

**Status: Phase 1–3 implementation in progress; VM deployment under validation**

## Purpose

求人、企業・技術動向、セキュリティニュース、脆弱性情報など、異なる公開ソースを共通の収集・正規化・保存パイプラインで扱う。特定分野や特定のAIサービスには依存しない。

- **入力**: 利用が認められた公開RSS、API、Webページ
- **処理**: 定期取得、変更検出、正規化、重複排除、履歴記録
- **保存**: 単一VM上のPostgreSQL
- **実行**: rootless Podman + systemd Quadlet
- **提供**: Access保護付きのブラウザUI、読み取り専用API、Remote MCP
- **公開リポジトリ**: ソースコード、収集先設定、スキーマ、設計書のみ。秘密情報・私的な転職情報・第三者の本文転載は含めない

## Architecture documents

1. [System architecture](docs/ARCHITECTURE.md) — 目的、責務、パイプライン、運用上の不変条件
2. [Data contracts](docs/DATA_MODEL.md) — ソース定義、取得記録、版管理、出典
3. [Podman / Quadlet deployment](docs/QUADLET_DEPLOYMENT.md) — 単一VM構成、rootless起動、秘密情報、バックアップ
4. [Implementation plan](docs/IMPLEMENTATION_PLAN.md) — 順序、検証、受入条件
5. [Quasar information portal UI](docs/UI_DESIGN.md) — ブラウザ描画、Feedly型の情報階層、実装範囲と受入条件
6. [Frontend execution policy](docs/FRONTEND_EXECUTION_POLICY.md) — VMとブラウザの実行責務
7. [Remote MCP and Cloudflare Access](docs/REMOTE_MCP_ACCESS.md) — 今後のTunnel/Managed OAuth/MCP公開設計

## Design principles

- 公開・適法なデータだけを収集し、サイトの利用条件・robots.txt・レート制限を尊重する。
- 収集した**事実と推論**、**原データと派生データ**、**収集基盤と利用者個人の評価**を分離する。
- 同じ情報を再取得しても重複しない一方、情報の変化は再現できるよう保存する。
- Gitは実装・設定の正本、PostgreSQLは実行時データの正本。
- 開発・検証なしに運用可能とは主張しない。

## Initial technology direction

Python、FastAPI、PostgreSQL、Podman Quadletを採用する。スケジューリングとジョブ実行はPostgreSQLを協調基盤として実装し、初期段階でRedis・Kafka・Kubernetes・Elasticsearch・n8nは導入しない。

実装は `src/nous/`、読み取り専用SPAは `ui/`、ソース定義は `sources/`、Quadletは `deploy/quadlet/` にあります。VMでの導入と検証手順は [運用手順](docs/OPERATIONS.md) を参照してください。
