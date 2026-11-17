---
title: セキュリティ
description: 脆弱性の非公開報告方法、セキュリティ修正を受け取るバージョン、PingWAF をインターネットへ公開する前に必要な強化手順。
minutes: 8
---

## 脆弱性の報告

PingWAF は保護対象アプリケーションのリクエスト経路に位置するため、その脆弱性は保護対象サイトの脆弱性と同じ重大度を持ちます。**公開の Issue・ディスカッション・Pull Request では報告せず**、非公開でご連絡ください。

- **GitHub の非公開脆弱性報告（推奨）:** [脆弱性を報告](https://github.com/shuaiZend/PingWAF/security/advisories/new)——非公開・追跡可能で、修正までの最短経路です。
- **メール:** `security@pingwaf.com`（2 名以上のメンテナが監視）。PGP 鍵は公開準備中です。指紋がここに掲載されるまでは、まず平文で概要をお送りください。暗号化用の鍵を返信します。

影響を受けるバージョン、実行モード（`all-in-one` / `server` / `agent`）、TLS バックエンド、再現手順、攻撃の前提条件を含め、トークンやパスワードは伏せてください。3 営業日以内に受領確認、修正中は毎週状況を共有し、修正リリース後（または 90 日後のいずれか早い方）に公開調整を行います。詳細は [SECURITY.md](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md) を参照してください。

## サポート対象バージョン

| バージョン | 状態 | セキュリティ修正 |
| --- | --- | --- |
| `0.32.x`（現行リリースライン） | サポート | あり |
| `0.31.x` | 重大な修正のみ | 依頼ベース・ベストエフォート |
| `0.30.x` 以前 | サポート終了（EOL） | なし |

セキュリティパッチが保証されるのは現行リリースラインのみです。セキュリティ修正はパッチリリースに含まれ、[変更履歴](https://github.com/shuaiZend/PingWAF/blob/main/CHANGELOG.md)の `### Security` に記載されます。

## 公開前の強化

コンソールには評価用の既定値が同梱されています。管理できないネットワークへ公開する前に:

1. **認証情報**——既定の管理者パスワードを変更し、`PINGWAF_JWT_SECRET` と `PINGWAF_SECRET_KEY` をそれぞれ 32 バイトの乱数に設定し、セルフサービス登録を無効化（`PINGWAF_ALLOW_REGISTRATION=false`）し、PostgreSQL の既定パスワードも変更します。
2. **ネットワーク**——コンソール（`9080`）はループバックまたはプライベートインターフェースにバインドし、VPN やリバースプロキシ経由でアクセスします。gRPC（`9090`）はエージェントホストのみに開放し、PostgreSQL（`5432`）は公開しないでください。
3. **TLS**——コンソール用の正式な証明書をアップロードするか、手前で TLS を終端します。各サイトで HTTPS と HSTS を有効化し、gRPC の TLS は有効のままにします。
4. **保存時の秘密**——`PINGWAF_SECRET_KEY` は通知チャネルの秘密、AI プロバイダキー、バックアップ対象の認証情報を暗号化します。未設定の場合これらは平文で保存されます。鍵は別途バックアップしてください（現時点でオンラインローテーションはありません）。
5. **ログ**——アクセスログはリクエスト/レスポンスヘッダ（`Authorization`、`Cookie`、`Set-Cookie` を含む）と最大 8 KiB のボディをそのまま保持し、既定の保持期間は 180 日です。PostgreSQL と Elasticsearch を認証情報ストアとして扱い、保持期間を短縮してください。
6. **MCP と AI**——MCP の `write` キーは fleet-wide の管理者資格情報です。`read` キーは所有者のサイトのみを参照します。内蔵 AI アシスタントはツール結果（サイト、ログ、WAF イベント、監査エントリ）を設定した外部プロバイダへ送信するため、そのデータがデプロイ外へ出てよい場合にのみ有効化してください。

環境変数・バックアップ手順・ローテーションの注意点を含む完全なチェックリストは [SECURITY.md](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md#hardening-checklist) と [docs/deployment.md](https://github.com/shuaiZend/PingWAF/blob/main/docs/deployment.md) にあります。