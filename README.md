# rpki-ca

一个使用 Rust 实现的 RPKI CA。它可以创建隔离测试用的 Trust Anchor、导入新签发的资源证书与匹配私钥、签发 RFC 9582 ROA 和 ASPA，并同步维护 CRL 和 RFC 9286 Manifest。ASPA 当前按 `draft-ietf-sidrops-aspa-profile-29` 实现，该规范尚未成为 RFC。

> 当前项目适合开发、协议验证和受控测试。若用于生产，还需要接入 HSM、RFC 8181 Publication Server、完善的身份与权限系统、审计日志、备份恢复和运行监控。

## 当前能力

- 创建开发用自签 Trust Anchor。
- 导入已有 TA 或 Resource Certificate（RC）及私钥。
- 按 RFC 9829 使用每级当前 Manifest 验证证书链、CRL、证书有效期、SIA 和逐级资源覆盖。
- 验证 ROA 前缀和 `maxLength` 是否被 CA 证书资源覆盖。
- 为证书、CRL 和 Manifest 分配持久化唯一序列号。
- 替换 ROA 时撤销旧 EE 证书。
- 通过可恢复的两阶段日志一致更新 ROA、CRL、Manifest、状态和本地仓库。
- 通过 JSON 文件或 CLI 参数提交 ROA 请求。
- 通过带 Bearer Token 和幂等保护的 HTTP API 提交 ROA 请求。
- 使用 CA 持有的 ASN 资源签发和验证 ASPA `.asa` 对象。
- 使用 Docker Compose 启动常驻 API 服务。

## 架构

`src` 按职责划分，入口、用例编排、领域模型和外部实现不再混放在同一目录：

```text
src/
├── main.rs                 # CLI 入口与公共类型导出
├── api/                    # HTTP 路由、鉴权与 DTO
├── application/            # 配置与 CaManager 应用用例
├── domain/                 # 签发请求及资源授权模型
├── ca/                     # CA 核心流程、对象签发、父链验证、状态模型
├── infrastructure/         # 文件仓库、状态存储、幂等存储、软件签名器
└── validation/             # 已发布 ROA/ASPA/CRL/Manifest 验证
```

- `CaManager`：应用层入口，负责加载 CA 并编排初始化、导入、签发和刷新命令。
- `CertificateAuthority`：单个 CA 的领域服务。
- `CertifiedResources`：封装证书中的 IPv4/IPv6/ASN 资源集合及授权判断。
- `ObjectIssuer`：构造并签名 ROA、ASPA、CRL 和 Manifest。
- `IssuedPublication`：ROA、ASPA 及后续签署对象共用的已签名发布事务输入。
- `ObjectDefinition`：描述期望签发的对象定义，目前包含 ROA 和 ASPA；它与已经签名发布的对象元数据分离。
- `ValidatedPublication`：资源授权、扩展名和逻辑身份均已验证的内部发布命令。
- 已发布对象使用 `kind + logical_key` 跟踪；ASPA 的逻辑键和文件名由 Customer ASN 稳定确定，更新 Provider 集合会替换旧对象并撤销旧 EE 证书。
- `PublicationRepository`：发布后端抽象；当前适配器是事务化的 `LocalRepository`。
- `SigningProvider`：对象签名抽象；当前适配器是 `SoftwareSigner`，未来可替换为 PKCS#11/HSM 实现。
- `CaStateStore`：CA 状态存储和排他锁抽象；当前适配器是 `LocalStateStore`。
- `IdempotencyStore`：API 幂等记录抽象；当前适配器是 `LocalIdempotencyStore`。
- `CaState`：纯状态模型，管理序列号、已签发对象、撤销记录和 Manifest 状态。
- HTTP API：薄适配层，CLI 和 API 最终调用相同的 `CaManager` 签发流程。

项目当前只生成一个名为 `rpki-ca` 的二进制 target。上述模块仍保持分层，但不额外生成容易与二进制混淆的 `rpki_ca` library target。

核心 CA 类型名是 `CertificateAuthority`。它不持有根目录或文件路径，只依赖 `SigningProvider`、`CaStateStore` 和 `PublicationRepository`。文件系统只是当前适配器的存储方式，并不是 CA 本身的领域含义。

## Docker Compose 快速开始

复制环境变量示例：

```bash
cp docker/.env.example docker/.env
```

至少应把 `.env` 中的测试令牌替换为足够长的随机值：

```dotenv
REPOSITORY_URI=rsync://localhost/rpki/
CA_NAME=development-ca
DEVELOPMENT_CA_VALIDITY_DAYS=365
CA_RENEW_BEFORE_DAYS=30
ROA_VALID_WEEKS=52
ASPA_VALID_WEEKS=52
PUBLISH_NEXT_HOURS=24
PUBLISH_NEXT_JITTER_HOURS=4
PUBLISH_HOURS_BEFORE_NEXT=8
CA_RESOURCES=192.0.2.0/24 2001:db8::/48
API_TOKEN=replace-with-a-long-random-token
API_PORT=3000
CORS_ORIGIN=http://localhost:5173
```

`CORS_ORIGIN` 是可选项。当前端和 API 不同源时，将它设置为前端的精确 Origin；不要填写路径，也不要使用 `*`。

`DEVELOPMENT_CA_VALIDITY_DAYS` 只控制开发 TA 证书。ROA 与 ASPA 的一次性 EE 证书分别使用 `ROA_VALID_WEEKS` 和 `ASPA_VALID_WEEKS`，默认均为 52 周；`notBefore` 回退 5 分钟以容忍时钟偏差，`notAfter` 不会超过签发 CA 证书。Manifest/CRL 默认使用 24 小时加 0～4 小时随机 jitter 的更新窗口。API 服务每 10 分钟检查一次，并在距离 `nextUpdate` 少于 8 小时时自动刷新。这些值只在首次初始化数据卷时写入 `ca.toml`，普通 ROA/ASPA API 请求不能覆盖它们。

构建并启动：

```bash
docker compose -f docker/compose.yaml up -d --build
docker compose -f docker/compose.yaml ps
```

API 默认监听 `http://127.0.0.1:3000`。容器内 CA 数据目录固定为 `/data`，并持久化在 `rpki-ca-data` 命名卷中。

上述 CA 初始化变量只在卷中不存在 `/data/ca.toml` 时生效。修改资源或仓库配置后若要从头创建测试 CA，可执行：

```bash
docker compose -f docker/compose.yaml down --volumes
docker compose -f docker/compose.yaml up -d
```

警告：`--volumes` 会永久删除测试 CA 私钥、状态和所有已发布对象。

## HTTP API

### 健康检查

```bash
curl http://localhost:3000/healthz
```

### 签发 ROA

```bash
API_TOKEN="与 docker/.env 中 API_TOKEN 相同的值"

curl --request POST http://localhost:3000/api/v1/roas \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header "Idempotency-Key: roa-request-001" \
  --header "Content-Type: application/json" \
  --data '{
    "asn": 64496,
    "prefixes": [
      { "prefix": "192.0.2.0/24", "max_length": 24 },
      { "prefix": "2001:db8::/48", "max_length": 48 }
    ]
  }'
```

响应示例：

```json
{
  "id": "8c69aa3fa8beb5a894e5cfcd45e94f30664ff5710eb77363cbb8cbdf65c18f0a",
  "object_name": "K2gN5Qx8Lc4sW9mT0pR7vY3aBzE.roa",
  "download_url": "/repository/K2gN5Qx8Lc4sW9mT0pR7vY3aBzE.roa",
  "created": true
}
```

接口列表：

- `GET /healthz`：健康检查，无需鉴权。
- `POST /api/v1/roas`：签发 ROA，要求 Bearer Token 和 `Idempotency-Key`。
- `GET /api/v1/roas/{id}`：查询幂等请求结果，要求 Bearer Token。
- `DELETE /api/v1/roas/{id}`：撤销并撤回该请求对应的 ROA，重复调用安全。
- `POST /api/v1/aspas`：签发 ASPA，要求 Bearer Token 和 `Idempotency-Key`。
- `GET /api/v1/aspas/{id}`：查询 ASPA 幂等请求结果，要求 Bearer Token。
- `DELETE /api/v1/aspas/{id}`：撤销并撤回该 Customer ASN 的 ASPA，重复调用安全。
- `GET /repository/{name}`：下载公开的 RPKI 仓库对象。

同一对象类型中，相同 `Idempotency-Key` 配合相同请求会返回已有结果，不会重新消耗序列号或重复签发；同一个 key 配合不同请求会被拒绝。幂等记录按 ROA/ASPA 命名空间隔离，因此两个对象类型可以安全地使用相同 key。ROA 和 ASPA 都使用其一次性 EE 公钥标识符生成 RFC 6481 推荐文件名；更新同一逻辑对象时会生成新 EE 密钥和新文件名，并原子替换原对象。API 将写请求串行执行，底层 CA 文件锁继续保护跨入口状态。

CLI 也支持撤销，并在同一事务中更新 CRL 和 Manifest：

```bash
rpki-ca withdraw-roa --dir data --object K2gN5Qx8Lc4sW9mT0pR7vY3aBzE.roa
rpki-ca withdraw-aspa --dir data --customer-asn 64496
```

## CLI

### 创建开发 TA

```bash
cargo run -- init \
  --dir data \
  --repository-uri rsync://localhost/rpki/ \
  --name development-ca \
  --development-ca-validity-days 365 \
  --resource 192.0.2.0/24 \
  --resource 2001:db8::/48
```

开发 TA 仅用于隔离测试，不属于公共 RPKI 信任链。

### 直接传入 ROA 参数

```bash
cargo run -- sign-roa \
  --dir data \
  --asn 64496 \
  --prefix 192.0.2.0/24 \
  --prefix "2001:db8::/48,48" \
  --output target/example.roa
```

`--prefix` 可以重复，每项支持以下两种形式：

```text
PREFIX
PREFIX,MAX_LENGTH
```

### 使用 JSON 请求

```bash
cargo run -- sign-roa \
  --dir data \
  --request examples/roa.json \
  --output target/example.roa
```

JSON 格式：

```json
{
  "asn": 64496,
  "prefixes": [
    { "prefix": "192.0.2.0/24", "max_length": 24 }
  ]
}
```

`--request` 与 `--asn`/`--prefix` 两种输入方式互斥。

### 在 Compose 容器中运行 CLI

```bash
docker compose -f docker/compose.yaml exec rpki-ca rpki-ca sign-roa \
  --dir /data \
  --asn 64496 \
  --prefix 192.0.2.0/24 \
  --output /tmp/cli-example.roa
```

### 刷新 CRL 和 Manifest

```bash
cargo run -- refresh --dir data
```

生产调度器应在 Manifest `nextUpdate` 之前运行刷新命令。当前更新窗口为 24 小时，建议至少每 12 小时执行一次。

### 签发 ASPA

开发 TA 初始化时必须显式配置 Customer ASN 资源：

```bash
cargo run -- init \
  --dir data \
  --resource 192.0.2.0/24 \
  --asn-resource 64496
```

签发 ASPA：

```bash
cargo run -- sign-aspa \
  --dir data \
  --customer-asn 64496 \
  --provider-asn 64497 \
  --provider-asn 64498 \
  --output target/aspa-64496.asa
```

HTTP 请求体格式：

```json
{
  "customer_asn": 64496,
  "provider_asns": [64497, 64498]
}
```

Provider ASN 会按数值排序并去重；列表不能为空，Customer ASN 不能出现在 Provider 列表中，AS0 只能作为唯一 Provider。Customer ASN 必须由 CA 资源证书覆盖。

## 导入已有 RC 或 TA

导入自签 TA：

```bash
cargo run -- import \
  --dir data \
  --certificate ta.cer \
  --private-key ta.key \
  --repository-uri rsync://rpki.example.net/repo/ta/ \
  --certificate-uri rsync://rpki.example.net/repo/ta/ta.cer \
  --serial-start 100000 \
  --crl-number-start 1 \
  --manifest-number-start 1
```

非自签 RC 必须提供完整认证路径。`--chain-certificate` 按 TA 到直接父 CA 排序；每个签发 CA 都必须提供相同顺序的当前 CRL 和当前 Manifest。例如 `TA -> parent -> child`：

```bash
cargo run -- import \
  --dir data \
  --certificate child.cer \
  --private-key child.key \
  --repository-uri rsync://rpki.example.net/repo/child/ \
  --certificate-uri rsync://rpki.example.net/repo/parent/child.cer \
  --serial-start 100000 \
  --crl-number-start 1 \
  --manifest-number-start 1 \
  --chain-certificate ta.cer \
  --chain-certificate parent.cer \
  --chain-crl ta.crl \
  --chain-crl parent.crl \
  --chain-manifest ta.mft \
  --chain-manifest parent.mft
```

导入会检查证书 Profile、有效期、私钥匹配、签名链、逐级解析后的资源、Manifest CMS/有效期、CRL 是否由证书 CRLDP 指定并由当前 Manifest 以匹配哈希列出、撤销状态，以及 SIA 发布地址。RFC 3779 `inherit` 会在认证路径上下文中解析并持久化。

`serial-start` 必须是该 CA 从未使用过的下一个证书序列号。当前版本只接受新签发且从未发布对象的 RC，因此 `crl-number-start` 和 `manifest-number-start` 必须都是 1。其他值会被明确拒绝；完整接管一个已有发布历史的 CA 还需要迁移其对象清单和撤销状态，不能只复制证书与私钥。

仅从 APNIC 等 RIR 公共仓库下载证书和对象，通常无法获得对应 CA 私钥，因此不能直接用下载内容冒充该 RC 签发新 ROA；实际签发必须使用由上级分配给你的资源证书和你自己控制的匹配私钥。

## 资源与输入语义

- `CA_RESOURCES` 或 `init --resource`：开发 TA 证书持有的 IP 资源上限。
- ROA `asn`：被授权宣告路由的 Origin ASN，不是用来签名的 CA 身份。
- ROA `prefixes`：准备授权给该 Origin ASN 的 IP 前缀。
- `max_length`：允许的最具体路由长度；省略时只允许 ROA 中给出的前缀长度。
- CA 私钥：签名所必需，不能从 RIR 公共仓库下载获得。
- RC 证书：决定 CA 可以授权的资源范围。

程序会拒绝空前缀集合、带主机位的网络、无效 `maxLength`，以及任何不被 CA 证书覆盖的 IP 前缀。签发前会按 RFC 9582 对前缀排序、去重，并省略与前缀长度相同的冗余 `maxLength`；ASN 0 按 RFC 9582 的 ASN.1 范围允许编码。

## 文件和发布

本地仓库位于 `<CA_DIR>/repository`，包含：

- `<ca-key-id>.cer`：CA 资源证书。
- `<ca-key-id>.crl`：当前 CRL。
- `<ca-key-id>.mft`：当前 Manifest。
- `<ee-key-id>.roa`：已签发 ROA。
- `<ee-key-id>.asa`：已签发 ASPA。

所有 `<key-id>` 都采用 RFC 6481 推荐名称：对应公钥的 160 位 Key Identifier 使用 RFC 4648 URL/filename-safe Base64 编码并移除填充，结果固定为 27 个字符。ROA/ASPA 每次重签会生成新的一次性 EE 密钥，因此文件名也随之更新；状态、证书 SIA、Manifest 条目和实际文件会在同一发布事务中切换。CA 使用同一密钥续期时 CA/CRL/Manifest 名称保持稳定。导入非自签 RC 时，CA 证书名称仍以父 CA 发布的 `certificate_uri` 为准，系统不会擅自重命名父 CA 管理的对象。

CLI 的 `--output` 只是导出一份对象副本，必须位于 `<CA_DIR>/repository` 之外；发布仓库内的推荐名称由 CA 独占管理。

发布时先构造完整 staging 仓库，再进行目录级切换；失败时恢复旧仓库，启动时也会恢复中断留下的备份。这不是 RFC 8181 Publication Server，实现远程发布时仍需接入独立的 RFC 8181 服务。

## 开发检查

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Docker Compose 端到端测试

测试的 Compose 参数、CA 的 IP/ASN 资源、ROA 输入和 ASPA Customer/Provider ASN 统一定义在 `tests/e2e/config.sh`。启动和清理由两种对象测试复用。

默认一次启动 Compose 并依次测试 ROA 和 ASPA：

```bash
bash tests/e2e/0_run.sh
```

也可以只测试一种对象，方便定位问题：

```bash
bash tests/e2e/0_run.sh roa
bash tests/e2e/0_run.sh aspa
```

`all` 模式只构建和启动一次容器，随后分别执行两种对象的签发、下载、密码学验证和 API 幂等测试，最后统一清理；因此它适合作为日常完整回归和 CI 默认入口。`roa`、`aspa` 模式使用同一套启动和清理代码，适合开发过程中快速验证单一对象。

完整流程会构建并启动专用 Compose 环境、初始化测试 CA、等待 API、提交固定 ROA 请求、下载四个发布对象、输出大小和 SHA-256、在容器内执行密码学验证、验证 API 幂等性，最后自动删除测试容器、网络、数据卷和临时文件。任一步失败时，会先打印容器日志再清理，并以非零状态退出。默认使用宿主机端口 `3100`；可通过 `RPKI_CA_E2E_PORT` 临时修改。

正常执行时会隐藏 Docker 构建和资源创建的详细输出，只显示测试步骤、输入、关键结果及 `PASS`。完整 Compose 构建输出保存在测试临时目录中，仅在构建或启动失败时打印。脚本使用兼容旧版本的 `curl --fail`。

更多文档：

- [架构与调用链](docs/architecture.md)
- [Docker Compose 与 API](docs/docker-compose.md)

## CA 证书生命周期

`CA_RENEW_BEFORE_DAYS`（默认 30 天）定义 CA 证书到期预警窗口。API 服务每次执行定时发布检查时也会检查证书有效期，并在进入窗口后输出告警。可以通过 CLI 或 HTTP API 随时读取状态：

```bash
rpki-ca certificate-status --dir data

curl http://localhost:3000/api/v1/ca/certificate \
  --header "Authorization: Bearer ${API_TOKEN}"
```

续期操作只接受父 CA 为当前密钥新签发的 DER 证书。新证书必须保持主体、公钥、资源集合和发布 URI 不变，并且 `notAfter` 必须晚于当前证书。非自签 RC 仍需提供从 TA 到直接父 CA 的完整证书链，以及每级当前 CRL 和 Manifest：

```bash
rpki-ca renew-certificate \
  --dir data \
  --certificate renewed-child.cer \
  --chain-certificate ta.cer \
  --chain-certificate parent.cer \
  --chain-crl ta.crl \
  --chain-crl parent.crl \
  --chain-manifest ta.mft \
  --chain-manifest parent.mft
```

HTTP 入口为 `POST /api/v1/ca/certificate-renewals`，字段为 `certificate_base64`、`chain_base64`、`crls_base64` 和 `manifests_base64`；后三项为数组。服务成功后返回 `204 No Content`。例如自签开发 TA 的请求体可生成如下：

```bash
jq -n --arg certificate "$(base64 < renewed-ta.cer | tr -d '\n')" \
  '{certificate_base64: $certificate}' > renewal.json

curl --request POST http://localhost:3000/api/v1/ca/certificate-renewals \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header "Content-Type: application/json" \
  --data @renewal.json
```

续期会在同一个可恢复发布事务中替换当前 `<key-id>.cer` 并重签 `<key-id>.crl` 和 `<key-id>.mft`；同密钥、同资源条件下名称不变，已有 ROA/ASPA 保持有效。更换 CA 密钥不属于本操作，必须通过 RFC 6489 的双密钥 key-roll 状态机完成，目前尚未实现。
