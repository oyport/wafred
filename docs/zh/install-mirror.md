# 安装脚本的 GitHub 与 GHCR 加速

Compose 安装脚本和二进制安装脚本均支持 `--mirror` 或 `WAFRED_MIRROR`。默认不使用加速站，仍从官方 GitHub 地址下载。`--mirror-mode host-path`（默认）把原地址的协议去掉后接在加速站后面，例如：

```text
https://raw.githubusercontent.com/oyport/wafred/main/install.sh
→ https://mirror.example.com/raw.githubusercontent.com/oyport/wafred/main/install.sh
```

如果加速站在同一前缀提供 OCI 镜像服务，Compose 安装脚本还会把 `ghcr.io/oyport/wafred` 映射为 `mirror.example.com/ghcr.io/oyport/wafred`，并把 `WAFRED_IMAGE` 写入 `.env`。之后运行 `docker compose pull` 会继续使用该镜像地址。

有些服务对文件和镜像使用不同的地址规则。例如 [GH-Proxy 的 GitHub 文件说明](https://gh-proxy.com/docs/github-accelerator)使用完整 URL 前缀，[Docker 镜像说明](https://gh-proxy.com/docs/docker-mirror)使用 `/docker/` 前缀。此时分别指定 `--mirror-mode full-url` 与 `--image-mirror`：

```bash
curl -fsSL https://gh-proxy.org/https://raw.githubusercontent.com/oyport/wafred/main/deploy/compose/install.sh \
  | bash -s -- --mirror https://gh-proxy.org --mirror-mode full-url \
      --image-mirror https://gh-proxy.org/docker
```

这会从代理下载安装脚本和 Compose 文件，并在 `.env` 中使用 `gh-proxy.org/docker/ghcr.io/oyport/wafred` 作为 WAFred 镜像。已有 `.env` 会保留其他设置；再次指定镜像加速站时只更新 `WAFRED_IMAGE`。`--force` 才会重写整份 `.env`。Compose 中的 PostgreSQL 镜像仍从 Docker Hub 获取。

二进制加 systemd 的安装方式只需要 GitHub 文件代理，不需要 OCI 镜像代理：

```bash
curl -fsSL https://gh-proxy.org/https://raw.githubusercontent.com/oyport/wafred/main/install.sh \
  | sudo bash -s -- --mirror https://gh-proxy.org --mirror-mode full-url \
      --mode all-in-one
```

二进制脚本会通过同一前缀查询 GitHub 最新 Release，并下载对应安装包。如果所选加速站不代理 `api.github.com`，可再加 `--version 1.0.0`（或其他已发布版本）跳过查询。最初获取脚本的 `curl` URL 也必须使用加速地址，脚本参数无法改变这一步。选择可信的加速站，确认其支持相应的 URL 格式；安装器不会关闭 TLS 证书校验。
