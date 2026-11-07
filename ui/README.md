# Nous OSINT — browser UI

Quasar 2 / Vue 3 / TypeScript の静的 SPA。履歴モードのルーティングを使用し、公開情報の観測レコード、変更履歴、情報源、CVE / KEV、管理機能を同じワークスペースで操作します。レポートの閲覧は別の Astro 静的出版物（`reports/site/`）です。

## Local development

Node.js 24（または 22.22+）と、`127.0.0.1:8000` で動作する独立した Nous API が必要です。

```sh
cd ui
npm ci
npm run dev
```

開発サーバーは `http://127.0.0.1:9000`。Vite の `/v1` プロキシはローカル開発専用で、認証境界ではありません。

## Validation

```sh
npm run typecheck
npm run build
```

成果物は `ui/dist/spa` に生成されます。コードのビルド成功とブラウザの表示・操作・認証検証は別の受入条件です。

## Production paths and ownership

- `/explore` / `/items/:id`：検索、カーソルでの追加読込、出典、観測履歴。
- `/changes`：7/30/90日の変更一覧。
- `/sources` / `/sources/new`：収集状態の閲覧、Gitレビュー用の公式定義生成。
- `/cves/:id`：CISA KEVの確認状態と根拠レコードの対応。
- `/admin/sources` / `/admin/reports`：Access と origin のロールで保護された書込・ジョブ管理。
- `/reports/`：同一ホストの別系統で配信する記事・根拠閲覧（SPA ルートではありません）。

本番の SPA 静的ファイルは Cloudflare Workers Static Assets の限定ルートから独立リリースされます。VMホストのMCPイメージに含まれる UI はフォールバックとして残します。`/v1/*`、MCP / OAuth、`/reports/*` の動的・出版ルートは既存の Access/Tunnel 経路が正本です。静的アセット以外のURLをWorkerへ包括転送しません。

実データだけを表示し、認証トークンや私的な収集結果を静的アセット・共有キャッシュに含めません。RSS/watch の未実装機能を UI 上で動作済みと示しません。

仕様と受入条件は [UI design contract](../docs/UI_DESIGN.md)、配信・認証の制約は [Edge frontend deployment](../docs/EDGE_FRONTEND_DEPLOYMENT.md) と [Frontend execution policy](../docs/FRONTEND_EXECUTION_POLICY.md) を参照してください。
