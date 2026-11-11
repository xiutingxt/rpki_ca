# Krill 发布仓库 Docker 部署

本目录提供独立的 Krill Publication Server、NGINX 和 rsyncd 部署，用于把自研 CA 的签名对象通过 RRDP/rsync 提供给验证器。

本文件说明 Docker 部署与数据保存。功能介绍、发布身份注册、CA 接入、同步命令和兼容性说明统一维护在 [Krill 发布仓库接入指南](../../docs/krill-publication.md)。以下命令均从**项目根目录**执行。

## 组件与地址

| 组件 | 职责 | 本机实验地址 |
|---|---|---|
| Krill | 接收 RFC 8181 发布、维护仓库数据 | 经 NGINX 的 `/rfc8181/` 接入 |
| NGINX | HTTPS 发布代理和 RRDP 文件服务 | `https://localhost:3443/` |
| rsyncd | 提供公开对象文件 | `rsync://localhost/repo/` |

地址只适用于在宿主机运行 CA 和验证器的实验。远程机器或其他容器需要提前配置双方可访问的域名及 TLS 证书。

Compose 仅启动发布仓库，不启动自研 CA，也不自动注册或同步对象。原有 API 服务使用独立的 `docker/compose.yaml`；两套服务的数据卷、管理 token 和入口不同。

## 启动仓库

需要 Docker Compose 和 OpenSSL。

部署入口：

```bash
cp docker/krill/.env.example docker/krill/.env
# 编辑 .env，设置自己的 KRILL_ADMIN_TOKEN。
bash docker/krill/generate-tls.sh
docker compose -f docker/krill/compose.yaml up -d --build
```

`generate-tls.sh` 只在首次生成证书时执行，已有证书不会被覆盖。启动后继续按 [接入指南](../../docs/krill-publication.md) 中的仓库初始化、身份注册和 CA 创建步骤操作。

## 文件与数据

| 文件 | 用途 |
|---|---|
| `compose.yaml` | 独立部署入口 |
| `krill.conf` | Krill 对外服务地址和数据目录 |
| `nginx.conf` | HTTPS 代理及 RRDP 路由 |
| `rsync.Dockerfile`、`rsyncd.conf` | rsync 服务 |
| `generate-tls.sh` | 生成本机实验 TLS 根和服务器证书 |
| `.env.example` | 管理 token 配置模板 |

Krill 状态和公开仓库保存在 Docker named volume。CA 数据与发布身份目录单独保存在所指定的本地路径；应保留 `publisher.key`、注册响应和 CA 状态。

停止服务并保留仓库数据：

```bash
docker compose -f docker/krill/compose.yaml down
```

更多细节见 [完整接入指南](../../docs/krill-publication.md)，项目主流程见 [主 README](../../README.md)。
