---
title: デプロイ
description: Docker Compose とソースビルド、ポート、設定の優先順位、systemd、分散エージェント。
minutes: 10
---

## デプロイ形態

**All-in-one** はコントロールプレーンとデータプレーンを 1 プロセスで動かします。単一ノード、評価、小規模構成に向きます。

**分散構成** は 1 つの `wafred server` と任意数の `wafred agent` を動かします。状態はコントロールプレーンにあり、エージェントはルールキャッシュ以外を持たないため、データベースに触れずにエッジを増やせます。

## ポート

| ポート | 用途 | 備考 |
| --- | --- | --- |
| `9080` | REST API + コンソール | 置き換えるまで自己署名証明書の HTTPS。私的なネットワークに置く |
| `9090` | gRPC コントロールプレーン | エージェントが接続。既定は TLS、`grpc_tls_mode = "off"` で平文 |
| `80` | プロキシ対象トラフィック | 最初のサイト作成後にバインド |
| `443` | プロキシ対象トラフィック | 証明書の発行またはアップロード後に開放 |

`GET /healthz` は HTTP と HTTPS の両方で応答するため、compose のヘルスチェックやロードバランサの監視に適しています。

## Docker Compose

```bash
git clone https://github.com/oyport/wafred.git
cd wafred
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

compose は `ghcr.io/oyport/wafred:latest` を all-in-one モードで `postgres:16-alpine` と一緒に起動し、`80`、`443`、`9080`、`9090` を公開します。データベースのポートは既定で `127.0.0.1` に束縛されます。

> `hostname` は安定させてください。コントロールプレーンは hostname と API key で再登録を突き合わせるため、コンテナ ID が変わると幽霊のようなオフラインノードが残ります。

## ソースからビルド

| ツール | バージョン | 理由 |
| --- | --- | --- |
| Rust | 1.96+（MSRV） | バイナリ本体 |
| Node.js | 26.12.1+ | 埋め込みコンソールのビルド（`engine-strict`） |
| `protoc` | 比較的新しいもの | gRPC コード生成。**必須** |
| `cmake` | 比較的新しいもの | TLS バックエンド |
| PostgreSQL | 14+（16 推奨） | コントロールプレーンの保存先 |

`protoc` がないと `pingwaf-proto` がプレースホルダを書き出し、後続のクレートがビルドできません。

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin wafred --features full
./target/release/wafred all-in-one \
  --db-url "postgres://wafred:wafred@localhost:5432/wafred"
```

Linux では `install.sh` がアーカイブを取得し、`/usr/local/bin` に導入、`/etc/wafred/wafred.toml` と systemd ユニットを作成してサービスを起動します。ターミナルで引数なしで実行すると対話ウィザード（モード、管理者認証情報、PostgreSQL URL、証明書 SAN、バージョン）が始まり、パイプで渡すと 1 行の無人インストールになります。

```bash
# 対話ウィザード：インストール計画の表示と確認つき
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh -o install.sh && bash install.sh

# 1 行・無人（パイプ経由は端末がないため質問なし）
curl -fsSL https://raw.githubusercontent.com/oyport/wafred/main/install.sh | bash -s -- --mode all-in-one
```

主なオプション：`--mode all-in-one|server|agent`、ユニット作成を省略する `--no-systemd`、質問なしで初期値を渡す `--admin-email` / `--admin-password` / `--tls-sans`（対応する `WAFRED_*` 環境変数でも可）、変更せずに計画だけ確認する `--dry-run`。

## 設定の優先順位

TOML、`WAFRED_*` 環境変数、CLI フラグの順に読み、後が優先されます。未知のキーは報告され無視されます。

```bash
wafred all-in-one --config /etc/wafred/wafred.toml
WAFRED_CONFIG=/etc/wafred/wafred.toml wafred all-in-one
```

`[server]` は `db_url`、`admin_addr`、`tls_enabled`、`tls_sans`、`grpc_addr`、`jwt_secret`、`admin_email`、`serve_frontend` を扱います。`[agent]` は `server_url`、`server_ca_cert`、`api_key`、`cache_dir`、`heartbeat_interval_secs`、ログのバッチ設定、`fail_open`、メトリクス送信を扱います。

## 分散エージェント

```bash
WAFRED_SERVER_URL="https://control.example.com:9090" \
WAFRED_API_KEY="<enrollment key>" \
WAFRED_CACHE_DIR="/var/lib/wafred/cache" \
wafred agent
```

登録キーはコンソールで作成します（`POST /api/v1/agents/enroll` がインストールコマンドを返します）。空の `WAFRED_API_KEY` は all-in-one のループバック自動登録でのみ有効です。

## systemd と TLS

同梱のユニットは `wafred` ユーザーで実行され、`Restart=always`、`LimitNOFILE=65536`、`ProtectSystem=strict` を設定し、書き込みは `/var/lib/wafred` と `/etc/wafred` に限定します。reload シグナルはなく、設定変更はコントロールプレーン経由、バイナリやユニットの変更は `systemctl restart wafred` が必要です。

コンソールは初回起動から自己署名証明書で HTTPS を提供します。生成前に `WAFRED_TLS_SANS` に実際のホスト名を設定するか、**設定 → コントロールプレーン HTTPS** で証明書をアップロードしてください。TLS 終端プロキシの背後に置く場合は `WAFRED_TLS_ENABLED=false` を設定します。
