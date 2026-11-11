# 全部流程使用 Docker

宿主机只需要运行中的 Docker 和 Docker Compose，无需 Rust/Cargo、Python 或 OpenSSL。项目默认在 Linux 下运行，Windows 使用 Git Bash；所有入口统一为 Bash 脚本。原有本机 CLI 与脚本继续保留。

以下命令在项目根目录的 Linux Bash 或 Windows Git Bash 中执行。首次构建需要联网下载镜像、Rust 依赖和工具包：

```bash
docker build -f docker/Dockerfile -t rpki-ca:0.1.0 .
docker build --target tools -f docker/Dockerfile -t rpki-ca-tools:local .
```

普通运行镜像只包含 CA 程序；工具镜像额外包含 Python、Bash、OpenSSL 和辅助脚本。两个目标复用 Rust 构建缓存。

## 一次性实验

```bash
bash scripts/rpki-ca-docker.sh experiment --request examples/experiment.json --output data/experiments/docker-001
bash scripts/rpki-ca-docker.sh verify-experiment --dir data/experiments/docker-001
bash scripts/verify-experiment-docker.sh --dir data/experiments/docker-001
```

`experiment` 在容器内创建临时 CA，签发、导出并验证，最后删除临时私钥。输出目录必须不存在。独立 OpenSSL 检查仅覆盖文件清单、哈希和 CMS 签名，不能替代完整的 `verify-experiment`。

新材料包使用格式 v4：输出的 `experiment.json` 在 `files.<文件名>.decoded` 中保存从实际 DER 文件解码的结果。签名对象的实际载荷位于 `decoded.eContent`，CMS 和内嵌 EE 证书信息位于 `decoded.cms`；原来的预期定义仍在 `objects.<文件名>.definition`。导出快照和 Compose/API 批量实验也包含这些解码结果。

## 保留 CA，持续签发

```bash
bash scripts/rpki-ca-docker.sh check-config --config examples/ca.toml
bash scripts/rpki-ca-docker.sh init --dir data/docker-cli/ca --config examples/ca.toml
bash scripts/rpki-ca-docker.sh sign-roa --dir data/docker-cli/ca --asn 64496 --prefix 192.0.2.0/24 --output data/docker-cli/example.roa
bash scripts/rpki-ca-docker.sh export-experiment --dir data/docker-cli/ca --output data/experiments/docker-snapshot-001
```

ASPA、TOA、SiSPI、刷新、撤回、换证等命令同样通过该入口执行；参数与 README 的本机 CLI 相同。项目目录挂载到 `/work`，相对路径以项目根目录为准，绝对路径必须使用容器路径，例如 `/work/data/docker-cli/ca`。项目外的输入先复制到项目内，或自行使用 `docker run --mount` 挂载。整个 CA 目录保留在宿主机，不随临时容器退出而删除。

## Compose/API 批量实验

```bash
cp docker/.env.example docker/.env
# 编辑 docker/.env，设置自己的 API_TOKEN。
bash scripts/experiment-compose.sh --request examples/experiment.json --output data/experiments/compose-001
```

批量脚本在工具容器内检查已有 CA、转换实验 JSON、生成 Compose 环境、等待 API 就绪并批量提交，然后在 CA 容器内导出并验证快照。宿主机负责调用 Docker、管理路径和移动导出目录，不执行 Python。工具容器通过 `--network container:<CA容器ID>` 访问服务，不挂载 Docker socket。

默认保留服务和 `data/compose-experiment` 中的 CA。复用 CA 时检查资源与关键配置是否匹配；导出包含 CA 当前持有的全部对象。`--down-after` 停止服务并保留 CA 数据；`--no-build` 要求事先构建 CA 和工具两种镜像。验证失败时保留诊断快照。完整选项见 `bash scripts/experiment-compose.sh --help`。

可用 `RPKI_CA_TOOLS_IMAGE` 环境变量指定工具镜像；通用 CLI 入口用 `RPKI_CA_IMAGE` 指定运行镜像。Linux CLI 和辅助准备容器按调用者 UID/GID 写入文件；Compose 服务仍按其原有用户运行。

## 导入 CA

将证书、匹配私钥及验证材料放入挂载目录，然后按[导入指南](import-ca.md)执行命令，把 `"$BIN"` 换成 `bash scripts/rpki-ca-docker.sh`。保留导入后的完整 CA 目录，再使用同一入口签发和导出。不得把 CA 私钥包含在对外分发的材料包中。

## Krill 仓库

Krill 服务继续使用[独立 Compose 部署](../docker/krill/README.md)。实验 TLS 证书也可以在工具容器里生成，不必安装本机 OpenSSL：

```bash
PROJECT_DIR="$(pwd -P)"
if command -v cygpath >/dev/null 2>&1; then PROJECT_DIR="$(cygpath -m "$PROJECT_DIR")"; fi
MSYS_NO_PATHCONV=1 docker run --rm --entrypoint bash --mount "type=bind,source=$PROJECT_DIR,target=/work" --workdir /work rpki-ca-tools:local /work/docker/krill/generate-tls.sh
```

按[接入指南](krill-publication.md)完成注册、配置和同步，把 CA 的 `"$BIN"` 命令换成通用 Docker CLI 入口。CA 与 publisher 私钥目录均持久化在宿主机。签发/撤回/刷新仍需显式执行 `publisher sync`。

先确定容器可达的 publication endpoint、公开 rsync/RRDP 地址和匹配 TLS 证书；原宿主机示例中的 `localhost` 不能直接用于普通 CA 容器访问其他容器。可通过 `RPKI_CA_DOCKER_NETWORK` 指定 CLI 加入的 Docker 网络，并使用该网络中可解析、证书认可的服务域名。配置地址不会自动修改已初始化的 Krill 或已有 CA 证书；必须在注册和创建 CA 前确定部署地址。

## 路径兼容

Bash 包装脚本统一处理 Linux 和 Git Bash 路径：禁用 Git Bash 对容器参数的自动路径转换，并将挂载源转换为 Docker 可识别的宿主机路径。各 CLI 参数保持一致。
