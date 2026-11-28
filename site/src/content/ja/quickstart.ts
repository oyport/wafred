import type { QuickStartContent } from "../schema";

const quickstart = {
  meta: {
    title: "クイックスタート — WAFred",
    description:
      "Docker Compose またはソースから WAFred を起動し、ログインして最初のサイトを追加し、エッジでルールを適用します。",
  },
  hero: {
    eyebrow: "クイックスタート",
    title: "5 分で起動、10 分で保護",
    lead: "公式の 2 つの道筋。評価には同梱の compose、本番には自前ビルド。",
    badges: [
      { icon: "container", label: "方法 A", value: "Docker Compose" },
      { icon: "code", label: "方法 B", value: "ソースからビルド" },
      { icon: "clock", label: "所要", value: "約 5 分" },
      { icon: "database", label: "保存先", value: "PostgreSQL 14+" },
    ],
    toc: [
      { id: "prerequisites", label: "前提条件" },
      { id: "docker", label: "Docker Compose" },
      { id: "source", label: "ソースから" },
      { id: "credentials", label: "初回ログイン" },
      { id: "next", label: "次のステップ" },
      { id: "troubleshooting", label: "トラブルシュート" },
    ],
  },
  prereq: {
    title: "始める前に",
    lead: "compose なら Docker だけで十分です。ソースからビルドする場合は Rust、Node、protoc が必要です。",
    items: [
      {
        label: "Docker",
        value: "Engine 24+ と Compose v2",
        note: "コントロールプレーン、エージェント、PostgreSQL をまとめて起動します。",
      },
      {
        label: "PostgreSQL",
        value: "14+（16 推奨）",
        note: "サイト、ルール、バージョンを保存します。ネイティブインストールのパッケージ名はディストリビューションによって異なります（Ubuntu 24.04 は postgresql-16、26.04 は postgresql-18）— apt-cache search --names-only '^postgresql-[0-9]+$' で確認してください。",
      },
      {
        label: "ポート",
        value: "9080 · 9090 · 80 · 443",
        note: "9080 が API とコンソール、9090 が gRPC です。",
      },
      {
        label: "TLS",
        value: "初回起動時は自己署名",
        note: "コンソールを公開する前に置き換えるか信頼してください。",
      },
    ],
  },
  paths: {
    docker: {
      id: "docker",
      title: "Docker Compose",
      lead: "compose は all-in-one モードで WAFred を PostgreSQL と一緒に起動します。",
      steps: [
        {
          title: "リポジトリを取得",
          body: "compose とサンプル TOML はリポジトリ直下にあります。",
          code: {
            lang: "bash",
            code: "git clone https://github.com/oyport/wafred.git\ncd wafred",
          },
        },
        {
          title: "スタックを起動",
          body: "外部から到達できるホストでは JWT_SECRET と ADMIN_PASSWORD を先に設定します。sudo なし（かつ docker グループ未所属）では compose は permission denied … docker.sock で失敗します。docker グループ所属のユーザーは sudo を省けます。",
          code: {
            lang: "bash",
            code: "export JWT_SECRET=\"$(openssl rand -hex 32)\"\nexport ADMIN_PASSWORD=\"$(openssl rand -hex 16)\"\n# docker グループ所属なら sudo は不要\nsudo docker compose up -d",
          },
        },
        {
          title: "コンソールを開く",
          body: "初回起動で生成した自己署名証明書で HTTPS を提供するため、信頼するか独自証明書をアップロードするまでブラウザは警告します。新規データベースではログイン自体は成功しますが、初期パスワードを変更するまで、すべての書き込み操作は 403 password_change_required を返します — 「設定 → アカウント」から、または PUT /api/v1/auth/password（current_password / new_password を渡す。成功時は 204 を返し、現在のトークンは失効するため新しいパスワードで再ログインが必要）で変更してください。",
          code: {
            lang: "bash",
            code: "curl --connect-timeout 2 --max-time 3 http://localhost:9080/healthz\n# {\"status\":\"ok\",\"database\":\"up\"}",
          },
        },
        {
          title: "最初のサイトを追加",
          body: "エージェントに向けるドメインでサイトを作成し、そのサイトに必要な防御だけを有効にします。",
        },
      ],
      note: "公開バイナリは Linux amd64/arm64 向けです。Docker イメージは両アーキテクチャに対応します。",
      shot: {
        key: "sites",
        url: "localhost:9080/sites",
        caption: "サイト一覧が適用の起点です。1 行が 1 ホスト名に対応します。",
        alt: "トラフィックと保護状態を表示するコンソールのサイト一覧",
      },
    },
    source: {
      id: "source",
      title: "ソースからビルド",
      lead: "独自ビルドや監査可能なバイナリが必要な場合の道筋です。",
      steps: [
        {
          title: "ツールチェーンを導入",
          body: "protoc は必須です。無い場合 proto クレートがプレースホルダに退避し、後続のクレートがビルドできません。",
          code: {
            lang: "bash",
            code: "# macOS\nbrew install protobuf\n\n# Debian / Ubuntu\nsudo apt install protobuf-compiler cmake",
          },
        },
        {
          title: "コンソールをビルド",
          body: "コンソールはバイナリに埋め込まれるため先にビルドします。",
          code: {
            lang: "bash",
            code: "cd web && npm ci && npm run build && cd ..",
          },
        },
        {
          title: "バイナリをビルド",
          body: "full フィーチャーには WAF エンジン、チャレンジ、証明書自動化が含まれます。",
          code: {
            lang: "bash",
            code: "cargo build --release --bin wafred --features full",
          },
        },
        {
          title: "all-in-one で起動",
          body: "PostgreSQL を指定します。スキーマは初回起動時に作成されます。",
          code: {
            lang: "bash",
            code: "./target/release/wafred all-in-one \\\n  --db-url \"postgres://wafred:wafred@localhost:5432/wafred\"",
          },
        },
      ],
      note: "Linux では install.sh（--mode all-in-one）でビルドを省略できます。",
      scene: {
        id: "agents",
        caption: "自前ビルドをコントロールプレーンとして動かし、後からエージェントを登録できます。",
        alt: "登録済みエッジエージェントとハートビートを表示するエージェントページ",
      },
    },
  },
  credentials: {
    title: "初回ログイン",
    lead: "コントロールプレーンは初回起動時に管理者を作成し、コンソールはパスワード変更を強制します — 「設定 → アカウント」から、または PUT /api/v1/auth/password（current_password / new_password を渡す。成功時は 204 を返し、現在のトークンは失効するため新しいパスワードで再ログインが必要）で変更してください。変更前は、すべての書き込み操作が 403 password_change_required を返します。",
    rows: [
      { label: "コンソール", value: "https://localhost:9080" },
      { label: "メール", value: "admin@wafred.local" },
      { label: "パスワード", value: "wafred123" },
      { label: "JWT シークレット", value: "16 文字以上" },
    ],
    warning: {
      title: "公開前に既定値を必ず変更",
      body: "WAFRED_JWT_SECRET と WAFRED_ADMIN_PASSWORD には動作する既定値があります。両方を設定し、WAFRED_ALLOW_REGISTRATION を false にし、9080 は社内ネットワークか VPN 内に留めてください。",
    },
    shot: {
      key: "login",
      url: "localhost:9080/login",
      caption: "初期管理者アカウントでログインします。パスキーは後から設定で登録できます。",
      alt: "メールアドレスとパスワード欄を備えた WAFred のログイン画面",
    },
  },
  next: {
    title: "次のステップ",
    lead: "コントロールプレーンが応答すれば、あとは設定だけです。",
    cards: [
      {
        icon: "globe",
        title: "サイトを作成",
        body: "サイトはドメインをオリジンプール、ルート、有効化した防御に結び付けます。",
        link: { label: "サイトモデル", path: "/docs/architecture/" },
      },
      {
        icon: "network",
        title: "エージェントを接続",
        body: "制御ノードで wafred server、各エッジで wafred agent を実行します。gRPC :9090 で登録されます。",
        link: { label: "分散デプロイ", path: "/docs/deployment/" },
      },
      {
        icon: "shield-check",
        title: "防御を有効化",
        body: "サイト単位で WAF エンジン、CC シールド、ボットポリシーを有効にします。有効にするまで何も適用されません。",
        link: { label: "機能", path: "/features/" },
      },
      {
        icon: "activity",
        title: "ログを外部へ",
        body: "リクエストログは Elasticsearch へ、生データは再現用に PostgreSQL へ保存します。",
        link: { label: "可観測性", path: "/features/#observability" },
      },
    ],
  },
  troubleshooting: {
    title: "起動しないとき",
    items: [
      {
        q: "wafred-proto でビルドが失敗する",
        a: "protoc がありません。protobuf-compiler（または brew install protobuf）を導入して再ビルドしてください。無い場合はプレースホルダに退避します。",
      },
      {
        q: "ブラウザが証明書を拒否する",
        a: "コンソールは自己署名証明書で HTTPS を提供します。ダウンロードした証明書を信頼するか、設定 → コントロールプレーン HTTPS で独自証明書をアップロードしてください。WAFRED_TLS_SANS で実際のホスト名を指定します。",
      },
      {
        q: "compose が \"failed to bind host port 127.0.0.1:5432/tcp: address already in use\" で失敗する",
        a: "ローカルの PostgreSQL がすでに 5432 を使用しています。POSTGRES_PORT=55432 で別のホストポートにマッピングして再起動してください（compose インストーラなら --db-port 55432 も渡せます。55432 以上の空きポートを自動選択します）。",
      },
      {
        q: "エージェントが一覧に出ない",
        a: ":9090 の gRPC に到達できるか（WAFRED_SERVER_URL）、ファイアウォールや TLS 終端プロキシに遮られていないかを確認してください。",
      },
      {
        q: "443 が開かない",
        a: "443 は証明書の発行またはアップロード後に開きます。それまではエージェントは 80 番の HTTP のみ提供します。",
      },
    ],
  },
  cta: {
    title: "詳しい手順が必要ですか",
    lead: "デプロイとアーキテクチャのドキュメントで、systemd、分散構成、設定の優先順位、環境変数の全一覧を説明しています。",
    primary: { label: "デプロイガイド", path: "/docs/deployment/" },
    secondary: { label: "GitHub", path: "https://github.com/oyport/wafred" },
  },
} satisfies QuickStartContent;

export default quickstart;
