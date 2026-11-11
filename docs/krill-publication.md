# Krill 发布仓库功能与接入指南

以下示例保留本机 CLI 用法；无需宿主机 Rust/OpenSSL 的容器入口及网络配置说明见 [Docker 使用指南](docker-workflows.md)。

本项目继续在本地 `repository/` 签发、撤回和维护 CRL/Manifest。新增 `publisher` 命令通过 RFC 8181 将一个已提交的完整快照同步至独立 Krill 发布服务。原有 CLI、HTTP API、离线实验和导出不要求启动 Krill。

每个 publisher 专属于一个 CA。同步会撤回该发布点中不在本地快照里的文件，因此不要与其他发布程序共用 publisher。本地签发成功与远端同步成功是两个独立状态；需要远程发布时，在签发、撤回或刷新后执行 `publisher sync`。

Docker 组件、配置文件和数据卷说明见 [Docker 部署 README](../docker/krill/README.md)。

## 1. 部署实验仓库

命令在项目根目录的 Linux Bash/Git Bash 执行。需要 Docker Compose、OpenSSL；rsync 拉取检查需要 rsync 客户端。本机配置使用 `localhost`，适用于在宿主机运行 CA 和验证器。其他容器或远程机器需要改用它们都能访问的域名。

```bash
cp docker/krill/.env.example docker/krill/.env
# 编辑 .env，设置自己的 KRILL_ADMIN_TOKEN。
bash docker/krill/generate-tls.sh
docker compose -f docker/krill/compose.yaml up -d --build
```

这是独立部署文件，不修改原 `docker/compose.yaml`。Krill 固定为 `v0.16.0`；NGINX 对宿主机提供 `https://localhost:3443/`，rsyncd 提供 `rsync://localhost/repo/`。它们只绑定宿主机回环地址。Krill 状态保存在 named volume；公开文件由 NGINX/rsyncd 只读访问，挂载整个数据根目录以避免 `rsync/current` 被目录替换后失效。

管理 API 不对外代理；通过容器内 CLI 初始化：

下面的初始化只对新仓库执行一次。后续启动复用现有 volume，继续使用已经注册的 publisher 和证书地址。实验 TLS 证书也只在首次生成时运行脚本。

```bash
docker compose -f docker/krill/compose.yaml exec \
  -e KRILL_CLI_SERVER=https://localhost:3000/ krill \
  sh -c 'KRILL_CLI_TOKEN="$KRILL_ADMIN_TOKEN" krillc pubserver server init --rrdp https://localhost:3443/rrdp/ --rsync rsync://localhost/repo/'
```

之后检查：

```bash
curl --cacert docker/krill/tls/ca.crt \
  https://localhost:3443/rrdp/notification.xml
rsync --list-only rsync://localhost/repo/
```

真实域名部署时，调整 `krill.conf` 的 `service_uri`、NGINX 配置、TLS 证书及初始化 URI。必须在注册 publisher 和创建 CA 前确定地址；已初始化的地址不能通过随意改配置迁移。正式证书可直接使用客户端内置公共根信任，内部证书使用 `--tls-ca` 添加信任；不提供关闭 TLS 验证的选项。

## 2. 注册发布身份

```bash
cargo build --locked
BIN=./target/debug/rpki-ca
if [ -f "$BIN.exe" ]; then BIN="$BIN.exe"; fi

mkdir -p data/krill
"$BIN" publisher init \
  --publisher-dir data/krill/publisher --handle my-ca
```

`publisher` 目录包含独立 BPKI 私钥 `publisher.key` 和 `publisher-request.xml`，不使用 CA 签发私钥。身份有效期为 10 年，Unix 下私钥权限为 `0600`、身份目录权限为 `0700`；Windows 下使用所在目录的 ACL。目录必须不存在，避免覆盖已有身份。

将请求注册至 Krill，保存返回的 Repository Response：

```bash
docker compose -f docker/krill/compose.yaml cp \
  data/krill/publisher/publisher-request.xml krill:/tmp/publisher-request.xml
docker compose -f docker/krill/compose.yaml exec -T \
  -e KRILL_CLI_SERVER=https://localhost:3000/ krill \
  sh -c 'KRILL_CLI_TOKEN="$KRILL_ADMIN_TOKEN" krillc pubserver publishers add --publisher my-ca --request /tmp/publisher-request.xml' \
  > data/krill/repository-response.xml

"$BIN" publisher configure \
  --publisher-dir data/krill/publisher \
  --response data/krill/repository-response.xml \
  --ca-config-output data/krill/new-ca.toml
```

Repository Response 是通过管理通道取得的信任材料：包含服务器 BPKI 身份、发布 endpoint、`sia_base` 和 RRDP notification URI。服务器分配的 handle 可以不同于请求中的 handle。客户端验证 XML 与身份凭证，并原子保存响应；不允许将已有 publisher 悄悄切换到不同仓库。

`--ca-config-output` 可选，只创建新文件，不修改现有 CA。编辑生成的 TOML，设置自己的资源、ASN 和有效期，然后创建新实验 CA：

```bash
"$BIN" check-config --config data/krill/new-ca.toml
"$BIN" init --dir data/krill/ca --config data/krill/new-ca.toml
```

生成配置的 `repository_uri` 来自实际 `sia_base`，新增可选字段 `rrdp_notification_uri` 会写入新建开发 CA 证书的 `rpkiNotify`。未设置该字段的旧配置仍按原行为运行；导入和换证时以所提供的证书地址为准。

生成模板采用普通 CA 默认值：IP 资源为文档示例网段，ASN 资源为空，CRL/Manifest 窗口为 24 小时加最多 4 小时随机偏移。签发 ASPA/SiSPI 前设置 `development_asns`；需要 30 天窗口时显式调整 `[timing]`。这与 `examples/ca.toml` 的 720 小时无随机偏移不同。

## 3. 签发与同步

继续使用原有签发入口。检查远端差异：

```bash
"$BIN" publisher sync \
  --publisher-dir data/krill/publisher --dir data/krill/ca \
  --tls-ca docker/krill/tls/ca.crt --dry-run
```

实际同步：

```bash
"$BIN" publisher sync \
  --publisher-dir data/krill/publisher --dir data/krill/ca \
  --tls-ca docker/krill/tls/ca.crt
```

输出包含 `publish`、`update`、`withdraw`、`unchanged` 与 `rrdp_advertised`。`--dry-run` 只发送签名 list 查询，不更改远端文件，也不创建 CA 绑定或成功记录。`--timeout-seconds` 默认为 30，范围 1～300。HTTP endpoint 默认拒绝，仅隔离实验可显式 `--allow-http`。

流程为：

1. 获取 publisher 跨进程锁，再获取 CA 状态锁。
2. 拒绝待提交的本地事务，验证 CA 信任链、当前 CRL、Manifest 与文件哈希，并拒绝 Manifest 未列出的杂文件（签发 CA 证书和 Manifest 自身除外）。
3. 验证发布 URI 和证书 SIA；发布目录可以是 `sia_base` 或其子目录。开发信任锚的 `certificate_uri` 必须指向实际发布的证书；使用已验证的同一组字节生成快照，再释放 CA 状态锁。
4. 使用独立 BPKI 身份签名 list 请求，并验证服务器 CMS 响应签名。
5. 按 SHA-256 计算新增、更新和撤回；更新/撤回携带远端旧哈希，一次提交完整变更。
6. 再查询远端确认与快照一致，保存 `last-sync.json`。重复同步没有变更时不发送写请求。

首次实际同步在请求发送前持久化 `ca-binding.txt`，绑定发布地址与 CA 公钥，避免失败重试时切换到另一 CA。网络请求期间不持有 CA 状态锁；同期新签发的对象会在下次同步发布。publisher 锁保证多个同步任务不会乱序提交。

超时、服务拒绝、响应签名错误均返回失败。遇到“远端已提交但响应丢失”，修复网络后重跑同一命令，重新 list 对账即可，不重签对象。本地仓库保持可用；失败不会伪造同步成功记录。`last-sync.json` 仅代表最后成功同步的快照，并不保证本地之后没有新变更。

API 服务会自动刷新本地材料，但不会自动同步 Krill。实验脚本可串联“签发/刷新 → 同步”；长期服务需要安排同步频率，确保在 CRL/Manifest 到期前发布刷新结果。

## 4. 对象和验证器兼容

同步模块发送签好的原始字节，不按扩展名过滤 ROA、ASPA、TOA、SiSPI、CRL 或 Manifest。TOA 和 SiSPI 的普通验证器解析支持仍需实验验证器提供，能从仓库下载不代表能被标准验证器解析。

已使用真实 Krill `v0.16.0` 验证四类签名对象及 CA/CRL/Manifest 的发布、重复同步、ASPA 替换和 SiSPI 撤回；通过 RRDP 校验快照哈希并逐字节比较本地文件，通过宿主机 rsync 端口核对独立部署中的公开材料。Compose 的 NGINX 配置使用本机缓存的 `nginx:1.27-alpine` 镜像完成联调；默认镜像是 `nginx:1.28-bookworm`，可用 `KRILL_NGINX_IMAGE` 覆盖。

新自签开发 CA 需要为验证器配置它的 TAL。可继续 `export-experiment` 获得 `trust-anchor.tal`，按所用验证器的自定义 TAL 流程安装。接入仓库不会获得公共 RPKI 信任。

对于已有 CA：证书中的 `caRepository` 必须等于分配的 `sia_base`，或位于其授权子目录内；例如分配 `/my-ca/`，可以在 `/my-ca/0/` 发布。客户端使用 `rpki::uri::Rsync` 校验目录边界，远端列表若含当前 CA 目录之外的对象则拒绝同步，不会清理其他目录。已有 `rpkiNotify` 也必须匹配返回地址；未包含 `rpkiNotify` 的 CA 可以通过 rsync 使用仓库，报告中 `rrdp_advertised` 为 false。修改 TOML 不会更新已有证书。导入 CA 的资源证书可能位于父级发布点，此时不将其迁移到子级路径；父级证书和信任链仍需从其原有位置访问。

对照 Krill `v0.16.0` 的 `ca_repo_sync` 和 `send_rfc8181_and_validate_response`：XML 交换、BPKI 证书、CMS 签名及验证、对象哈希和发布 PDU 均使用 `rpki` 库；HTTPS 传输使用 `reqwest`。保留完整 TLS 验证，通过 `--tls-ca` 信任实验 TLS 根，不采用 Krill 内部客户端的关闭 TLS 证书检查方式。身份和同步元数据使用原子替换，在 Unix 上同步父目录以保证提交的目录项持久化。

暂不实现仓库迁移、CA 公钥轮换后的重新绑定、发布身份轮换、多发布点及后台自动同步。它们不影响现有本地功能。

## 5. 停止实验服务

```bash
docker compose -f docker/krill/compose.yaml down
```

该命令保留仓库 volume。不要在需要恢复仓库时删除 volume，也不要丢失 BPKI 身份目录。

参考：[Krill Publication Server](https://krill.docs.nlnetlabs.nl/en/stable/publication-server.html)、[RFC 8181](https://www.rfc-editor.org/rfc/rfc8181.html)、[RFC 8183](https://www.rfc-editor.org/rfc/rfc8183.html)。
