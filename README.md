# rpki-ca

一个使用 Rust 实现的 RPKI CA。它可以创建隔离测试用的 Trust Anchor、导入资源证书与匹配私钥、签发 ROA、ASPA、实验性 TOA 和 SiSPI，并同步维护 CRL 和 Manifest。TOA 使用临时内容类型 OID `1.2.840.113549.1.9.16.1.999`；SiSPI 除使用临时内容类型 OID `1.2.840.113549.1.9.16.1.998` 外按 `draft-chen-sidrops-sispi-06` 实现。IANA 分配正式 OID 后必须替换对应常量并重新签发对象。

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
- 按 `draft-chen-sidrops-sispi-06` 签发和验证 SiSPI `.sav` 对象。
- 使用 Docker Compose 启动常驻 API 服务。

## 架构

`src` 按职责划分，入口、用例编排、领域模型和外部实现不再混放在同一目录：

```text
src/
├── main.rs                 # 仅负责启动并调用 cli::run()
├── lib.rs                  # library crate 模块边界与公共 API
├── cli/
│   ├── mod.rs              # CLI 模块声明与入口导出
│   ├── args.rs             # clap 参数、子命令和 CLI 输入类型
│   ├── commands.rs         # 各子命令的应用层调用与输出
│   └── io.rs               # 文件读取和外部导出路径检查
├── api/                    # HTTP 路由、鉴权与 DTO
├── application/            # 配置与 CaManager 应用用例
├── domain/                 # 签发请求及资源授权模型
├── ca/                     # CA 核心流程、对象签发、父链验证、状态模型
├── infrastructure/         # 文件仓库、状态存储、幂等存储、软件签名器
└── validation/             # TAL 完整路径、当前发布点及各类签名对象验证
```

- `CaManager`：应用层入口，负责加载 CA 并编排初始化、导入、签发和刷新命令。
- `CertificateAuthority`：单个 CA 的领域服务。
- `CertifiedResources`：封装证书中的 IPv4/IPv6/ASN 资源集合及授权判断。
- `ObjectIssuer`：构造并签名 ROA、ASPA、TOA、SiSPI、CRL 和 Manifest。
- `IssuedPublication`：ROA、ASPA 及后续签署对象共用的已签名发布事务输入。
- `ObjectDefinition`：描述期望签发的 ROA、ASPA、TOA 或 SiSPI；它与已经签名发布的对象元数据分离。
- `ValidatedPublication`：资源授权、扩展名和逻辑身份均已验证的内部发布命令。
- `Params::signed_object_builder()`：所有对象共用的 RFC 6488 EE/CMS 参数构造入口。
- `ProfiledSignedObject`：TOA、SiSPI 等本地 Profile 共用的 RFC 6488 编码和 CMS/EE/CRL 验证骨架；各对象仍独立负责 ASN.1 与资源规则。
- 已发布对象使用 `kind + logical_key` 跟踪；ASPA 的逻辑键和文件名由 Customer ASN 稳定确定，更新 Provider 集合会替换旧对象并撤销旧 EE 证书。
- `PublicationRepository`：发布后端抽象；当前适配器是事务化的 `LocalRepository`。
- `SigningProvider`：对象签名抽象；当前适配器是 `SoftwareSigner`，未来可替换为 PKCS#11/HSM 实现。
- `CaStateStore`：CA 状态存储和排他锁抽象；当前适配器是 `LocalStateStore`。
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
RPKI_CA_IMAGE_NAME=rpki-ca
RPKI_CA_IMAGE_VERSION=0.1.0
REPOSITORY_URI=rsync://localhost/rpki/
CA_DATA_DIR=../data/docker
CA_NAME=development-ca
DEVELOPMENT_CA_VALIDITY_DAYS=365
CA_RENEW_BEFORE_DAYS=30
ROA_VALID_WEEKS=52
ASPA_VALID_WEEKS=52
SISPI_VALID_WEEKS=52
TOA_VALID_WEEKS=52
TOA_REVIEW_DAYS=90
PUBLISH_NEXT_HOURS=24
PUBLISH_NEXT_JITTER_HOURS=4
PUBLISH_HOURS_BEFORE_NEXT=8
CA_RESOURCES=192.0.2.0/24 2001:db8::/48
API_TOKEN=replace-with-a-long-random-token
API_PORT=3000
CORS_ORIGIN=http://localhost:5173
```

`CORS_ORIGIN` 是可选项。当前端和 API 不同源时，将它设置为前端的精确 Origin；不要填写路径，也不要使用 `*`。

`DEVELOPMENT_CA_VALIDITY_DAYS` 只控制开发 TA 证书。各对象的一次性 EE 证书分别使用 `ROA_VALID_WEEKS`、`ASPA_VALID_WEEKS`、`TOA_VALID_WEEKS` 和 `SISPI_VALID_WEEKS`，默认均为 52 周；`notBefore` 回退 5 分钟以容忍时钟偏差，`notAfter` 不会超过签发 CA 证书。`TOA_REVIEW_DAYS` 是 TOA 定期运行复核周期，默认 90 天（周期是本项目的可配置运行策略，草案只要求定期复核而未规定天数）。Manifest/CRL 默认使用 24 小时加 0～4 小时随机 jitter 的更新窗口。API 服务每 10 分钟检查一次，并在距离 `nextUpdate` 少于 8 小时时自动刷新。这些值只在首次初始化 CA 目录时写入 `ca.toml`，普通签发请求不能覆盖它们。

构建并启动：

```bash
docker compose -f docker/compose.yaml up -d --build
docker compose -f docker/compose.yaml ps
```

Compose 构建的镜像默认命名为 `rpki-ca:0.1.0`，版本与 `Cargo.toml` 一致。可通过 `.env` 中的 `RPKI_CA_IMAGE_NAME` 和 `RPKI_CA_IMAGE_VERSION` 自定义镜像仓库名和标签。若本机已有使用旧匿名镜像创建的容器，请执行上面的 `up -d --build`；Compose 会用带名称和版本的新镜像重建容器。

API 默认监听 `http://127.0.0.1:3000`。`CA_DATA_DIR` 指定的宿主机目录绑定到容器的 `/var/lib/rpki`，CA 数据位于宿主机的 `<CA_DATA_DIR>/ca` 和容器的 `/var/lib/rpki/ca`。默认的 `../data/docker` 相对于 `docker/compose.yaml`，即仓库根目录下的 `data/docker`。CA 子目录不能直接作为挂载点，因为初始化的原子目录切换需要替换该子目录。

上述 CA 初始化变量只在绑定目录中不存在 `/var/lib/rpki/ca/ca.toml` 时生效。修改资源或仓库配置后若要从头创建测试 CA，可执行：

```bash
docker compose -f docker/compose.yaml down
rm -rf data/docker/ca
docker compose -f docker/compose.yaml up -d
```

警告：删除 `data/docker/ca` 会永久删除测试 CA 私钥、状态和所有已发布对象。`docker compose down --volumes` 不会删除 bind mount 中的数据。

## HTTP API

### 健康检查

```bash
curl http://localhost:3000/healthz
```

### 管理 ROA 授权

```bash
API_TOKEN="与 docker/.env 中 API_TOKEN 相同的值"

curl --request POST http://localhost:3000/api/v1/roas \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header "Content-Type: application/json" \
  --data '{
    "added": [
      { "asn": 64496, "prefix": "192.0.2.0/24", "max_length": 24, "comment": "production" },
      { "asn": 64496, "prefix": "2001:db8::/48", "max_length": 48 }
    ],
    "removed": []
  }'
```

接口保存的是期望授权集合，实际 `.roa` 文件由 CA 自动派生。同一 ASN 的授权合并进一个 ROA；集合变化时旧 ROA 的 EE 证书被撤销，新 ROA、CRL 和 Manifest 在一次发布事务中提交。完全相同的授权再次加入会返回 `422 roa_delta_rejected`，并在 `details.duplicates` 中指出重复项，不会重新签发。

查询当前授权及其实际发布对象：

```bash
curl http://localhost:3000/api/v1/roas \
  --header "Authorization: Bearer ${API_TOKEN}"
```

接口列表：

- `GET /healthz`：健康检查，无需鉴权。
- `GET /api/v1/roas`：列出期望 ROA 授权及其派生发布对象，要求 Bearer Token。
- `POST /api/v1/roas`：原子应用 `{added, removed}` 授权增量；ROA 不使用 `Idempotency-Key`。
- `GET /api/v1/aspas`：列出当前 ASPA 定义及实际发布对象。
- `POST /api/v1/aspas`：原子应用 `{added, removed}` ASPA 批量增量；以 Customer ASN 为身份，重复提交是无操作，不使用 `Idempotency-Key`。
- `GET /api/v1/aspas/{customer_asn}`：按 Customer ASN 查询当前 ASPA；`DELETE` 同一路径撤回 ASPA。
- `GET /api/v1/toas`：列出当前 TOA 定义及实际发布对象。
- `POST /api/v1/toas`：创建实验性 TOA；按规范化内容摘要去重，重复提交返回 `unchanged`，不使用 `Idempotency-Key`。
- `GET /api/v1/toas/{key}`：按响应中的 64 位内容键查询当前 TOA；`DELETE` 同一路径撤回 TOA。
- `GET /api/v1/toas/reviews`：列出已发布 TOA 的最近复核时间、下次截止时间和 ROA 覆盖状态。
- `POST /api/v1/toas/{name}/reviews`：按 TOA 发布文件名重新检查其与当前 ROA 的覆盖关系并记录一次运行复核。
- `GET /api/v1/sispis`：列出当前 SiSPI 定义及实际发布对象。
- `POST /api/v1/sispis`：原子应用 `{added, removed}` SiSPI 批量增量；以 AS ID 为身份，重复提交是无操作，不使用 `Idempotency-Key`。
- `GET /api/v1/sispis/{as_id}`：按 AS ID 查询当前 SiSPI；`DELETE` 同一路径撤回 SiSPI。
- `DELETE /api/v1/signed-objects/{name}`：按当前 CA 签发清单中的发布文件名撤回 ASPA、TOA 或 SiSPI；ROA 必须通过授权增量移除，不能直接删除派生文件。
- `GET /api/v1/repository/objects`：列出当前真实发布仓库中的证书、CRL、Manifest、ROA、ASPA、TOA 和 SiSPI，要求 Bearer Token。
- `GET /api/v1/repository/objects/{name}`：严格解码仓库对象并返回结构化内容、SHA-256 和 Base64，要求 Bearer Token。
- `GET /api/v1/repository/objects/{name}/validation`：使用 `rpki` 库从配置的 TAL 开始验证全部父级 CA 证书、CRL 和 Manifest，再验证当前 CA 发布点的 CRL、Manifest、文件哈希、吊销状态以及 ROA/ASPA/TOA/SiSPI 的 CMS、EE 证书、Profile 和资源覆盖。导入 RC 使用最近一次提交的父级发布快照，本接口不会主动通过 RRDP/rsync 下载更新。
- `POST /api/v1/ca/validation-context`：更新导入 RC 的 TAL、父级证书、CRL 和 Manifest 本地快照；提交前会完整验证新路径并确认当前 CA 资源集合不变。
- `GET /repository/{name}`：下载公开的 RPKI 仓库对象。

对象详情接口的 `decoded` 不使用自定义的扁平字段名，而按对应 ASN.1 Profile 保留字段名和层级：证书按 RFC 6487 的证书字段与扩展展示；CRL 使用 `certificateList`、`revokedCertificates[].userCertificate/revocationDate` 和 `crlExtensions`；Manifest 使用 RFC 9286 的 `manifestNumber`、`thisUpdate`、`nextUpdate`、`fileHashAlg` 和 `fileList`；ROA、ASPA、TOA、SiSPI 的内容分别放在 `eContent` 中，并保留各自 RFC/Draft 定义的字段名。RFC 6488 的 CMS 外层统一放在 `cms` 中。`profile` 和 `summary` 是界面元数据，不属于对象 ASN.1 内容，因而与协议字段分开。

管理层统一采用“对象定义/授权配置 → 调和 → 实际发布对象”的模型，而不是把仓库文件名当作业务身份。ROA 保存逐条授权配置并按 Origin ASN 派生 ROA；ASPA 以 Customer ASN、SiSPI 以 `asID` 作为稳定逻辑身份；TOA 使用规范化 eContent 的摘要作为身份。所有写接口都由后端按规范化后的领域状态去重，不使用 `Idempotency-Key`。相同 TOA 内容返回 `unchanged`；删除后可以直接重新创建。一批有效变更只生成一组 CRL/Manifest，并通过可恢复的发布事务原子切换。

非 ROA 对象撤回成功后，API 返回对象类型和文件名、对象 EE 证书序列号、该证书是否因尚未过期而加入 CRL、撤销时间，以及新 CRL/Manifest 编号。例如：

```bash
curl --request DELETE \
  "http://localhost:3000/api/v1/signed-objects/K2gN5Qx8Lc4sW9mT0pR7vY3aBzE.asa" \
  --header "Authorization: Bearer ${API_TOKEN}"
```

```json
{
  "object_name": "K2gN5Qx8Lc4sW9mT0pR7vY3aBzE.asa",
  "kind": "aspa",
  "ee_certificate_serial": 10,
  "ee_certificate_revoked": true,
  "revocation_time": 1789460000,
  "crl_number": 6,
  "manifest_number": 6
}
```

撤回会生成新的 CRL 和 Manifest：未过期的对象 EE 证书进入 CRL，对象不再出现在发布目录和新 Manifest 中，上一份 Manifest 的一次性 EE 证书同时被撤销。CA 证书、CRL 和 Manifest 不是此接口的合法目标。整个变更沿用可恢复的原子发布事务。

CLI 也支持撤销，并在同一事务中更新 CRL 和 Manifest：

```bash
rpki-ca withdraw-aspa --dir data --customer-asn 64496
rpki-ca withdraw-toa --dir data --object K2gN5Qx8Lc4sW9mT0pR7vY3aBzE.toa
rpki-ca withdraw-sispi --dir data --as-id 64496
```

ROA 使用 `update-roas` 原子增删授权：

```bash
rpki-ca update-roas --dir data --delta /path/to/roa-delta.json
rpki-ca list-roas --dir data
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

### 在 Compose 容器中运行 CLI

```bash
docker compose -f docker/compose.yaml exec rpki-ca rpki-ca sign-roa \
  --dir /var/lib/rpki/ca \
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

### 签发 TOA

```bash
cargo run -- sign-toa \
  --dir data \
  --asn 64496 \
  --asn 64497 \
  --prefix 192.0.2.0/24 \
  --prefix 2001:db8::/48 \
  --output target/example.toa
```

HTTP 请求体为 `{"asns":[64496,64497],"prefixes":["192.0.2.0/24","2001:db8::/48"]}`。ASN 和前缀会按草案规范排序并去重；TOA EE 证书包含显式 IP Resources、禁止 inherit 且不包含 AS Resources。当前唯一非草案最终值是实验 OID `1.2.840.113549.1.9.16.1.999`。

签发前会把 TOA 展开为全部 `(ASN, 前缀)` 组合，并按 ROA 的前缀和 `maxLength` 检查现有 ROA。若全部组合均被 ROA 覆盖，必须在 JSON 中提供非空的 `roa_overlap_justification`（CLI 使用 `--roa-overlap-justification`）才能按运行例外继续签发；部分重叠不会拆分对象，响应的 `advisories` 会说明覆盖数量，并按草案建议保留一个合并 TOA。签发时会记录首次复核，下次截止时间由 `TOA_REVIEW_DAYS` 决定。

```bash
rpki-ca list-toa-reviews --dir data
rpki-ca review-toa \
  --dir data \
  --object K2gN5Qx8Lc4sW9mT0pR7vY3aBzE.toa \
  --roa-overlap-justification "traffic origin 与 route origin 的运维职责不同"
```

对应 API 复核请求体为 `{"roa_overlap_justification":"运行原因"}`。若复核时 TOA 已被 ROA 完全覆盖而未提供理由，复核会被拒绝，提醒操作员更新或撤回 TOA。

### 签发 SiSPI

开发 TA 或导入 RC 必须持有 `asID` 对应的 ASN 资源。SiSPI 输入中的地址是可达的 SAVNET Agent 单播地址，不是由 EE 证书承载的资源：

```bash
cargo run -- sign-sispi \
  --dir data \
  --as-id 64496 \
  --address 192.0.2.1 \
  --address 2001:db8::1 \
  --output target/sispi-64496.sav
```

HTTP 请求体：

```json
{
  "as_id": 64496,
  "addresses": ["192.0.2.1", "2001:db8::1"]
}
```

生成器按 IPv4、IPv6 和数值顺序规范化并去重地址。eContent 的 `version` 默认值 0 按 DER 要求省略；EE 证书仅包含覆盖 `asID` 的显式 AS Identifier Delegation Extension，禁止 `inherit`，且完全不包含 IP Address Delegation Extension。`.sav` 和 `application/rpki-sispi` 来自 SiSPI-06 草案；当前内容类型 OID `1.2.840.113549.1.9.16.1.998` 是本项目临时实验值，因为草案仍写作 TBD。

## 导入已有 RC 或 TA

导入自签 TA：

```bash
cargo run -- import \
  --dir data \
  --certificate ta.cer \
  --private-key ta.key \
  --tal trust-anchor.tal \
  --repository-uri rsync://rpki.example.net/repo/ta/ \
  --certificate-uri rsync://rpki.example.net/repo/ta/ta.cer \
  --serial-start 100000 \
  --publication-number-start 1
```

非自签 RC 必须提供完整认证路径。`--chain-certificate` 按 TA 到直接父 CA 排序；每个签发 CA 都必须提供相同顺序的当前 CRL 和当前 Manifest。例如 `TA -> parent -> child`：

```bash
cargo run -- import \
  --dir data \
  --certificate child.cer \
  --private-key child.key \
  --tal trust-anchor.tal \
  --repository-uri rsync://rpki.example.net/repo/child/ \
  --certificate-uri rsync://rpki.example.net/repo/parent/child.cer \
  --serial-start 100000 \
  --publication-number-start 1 \
  --chain-certificate ta.cer \
  --chain-certificate parent.cer \
  --chain-crl ta.crl \
  --chain-crl parent.crl \
  --chain-manifest ta.mft \
  --chain-manifest parent.mft
```

导入会检查证书 Profile、有效期、私钥匹配、签名链、逐级解析后的资源、Manifest CMS/有效期、CRL 是否由证书 CRLDP 指定并由当前 Manifest 以匹配哈希列出、撤销状态，以及 SIA 发布地址。RFC 3779 `inherit` 会在认证路径上下文中解析并持久化。

导入时使用的 TAL、父级证书、CRL 和 Manifest 会随 CA 状态持久化。对象验证接口每次都会重新使用这些材料验证完整路径，而不是把导入的 RC 当作本地信任锚。父级 CRL/Manifest 更新后，应在旧快照到期前更新验证上下文；此操作不更换当前 RC 或私钥：

```bash
rpki-ca update-validation-context \
  --dir data \
  --tal trust-anchor.tal \
  --chain-certificate ta.cer \
  --chain-certificate parent.cer \
  --chain-crl ta.crl \
  --chain-crl parent.crl \
  --chain-manifest ta.mft \
  --chain-manifest parent.mft
```

HTTP 入口为 `POST /api/v1/ca/validation-context`，请求字段是 `tal_base64`、`chain_base64`、`crls_base64` 和 `manifests_base64`。后端只在新快照能够验证当前 RC 且解析后的资源集合不变时保存；失败时继续保留原快照。

`serial-start` 必须是该 CA 从未使用过的下一个证书序列号。`publication-number-start` 同时作为首个 CRL Number 和 Manifest Number；当前版本只接受新签发且从未发布对象的 RC，因此该值必须是 1。完整接管一个已有发布历史的 CA 还需要迁移其对象清单和撤销状态，不能只复制证书与私钥。

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
- `<ee-key-id>.toa`：已签发实验性 TOA。
- `<ee-key-id>.sav`：已签发实验性 SiSPI。

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

测试的 Compose 参数、CA 资源以及所有签名对象输入统一定义在 `tests/e2e/config.sh`。启动和清理由所有对象测试复用。

默认一次启动 Compose 并依次测试 ROA、ASPA、TOA 和 SiSPI：

```bash
bash tests/e2e/0_run.sh
```

也可以只测试一种对象，方便定位问题：

```bash
bash tests/e2e/0_run.sh roa
bash tests/e2e/0_run.sh aspa
bash tests/e2e/0_run.sh toa
bash tests/e2e/0_run.sh sispi
```

`all` 模式只构建和启动一次容器，随后分别执行四种对象的签发、下载、密码学验证和 API 幂等测试，最后统一清理；因此它适合作为日常完整回归和 CI 默认入口。单对象模式使用同一套启动和清理代码，适合开发过程中快速定位问题。

完整流程会构建并启动专用 Compose 环境、初始化测试 CA、等待 API、依次提交固定对象请求、下载发布结果、在容器内执行密码学与发布集验证、验证 API 幂等性，最后自动删除测试容器、网络、数据卷和临时文件。任一步失败时，会先打印容器日志再清理，并以非零状态退出。默认使用宿主机端口 `3100`；可通过 `RPKI_CA_E2E_PORT` 临时修改。

正常执行时会隐藏 Docker 构建和资源创建的详细输出，只显示测试步骤、输入、关键结果及 `PASS`。完整 Compose 构建输出保存在测试临时目录中，仅在构建或启动失败时打印。脚本使用兼容旧版本的 `curl --fail`。

更多文档：

- [架构与调用链](docs/architecture.md)
- [Docker Compose 与 API](docs/docker-compose.md)
- [CA 功能验收测试](docs/ca-testing.md)

## CA 证书生命周期

`CA_RENEW_BEFORE_DAYS`（默认 30 天）定义 CA 证书到期预警窗口。API 服务每次执行定时发布检查时也会检查证书有效期，并在进入窗口后输出告警。可以通过 CLI 或 HTTP API 随时读取状态：

```bash
rpki-ca certificate-status --dir data

curl http://localhost:3000/api/v1/ca/certificate \
  --header "Authorization: Bearer ${API_TOKEN}"
```

当前 CA 证书实际授权的 ASN、IPv4 和 IPv6 资源可以通过只读接口查询：

```bash
curl http://localhost:3000/api/v1/ca/resources \
  --header 'Authorization: Bearer change-me'
```

返回格式与 Krill CA 详情中的资源摘要一致，例如
`{"asn":"AS64496","ipv4":"192.0.2.0/24","ipv6":"2001:db8::/48"}`。
该接口展示后端已解析并用于签发授权检查的真实资源，不允许绕过上级 CA
证书直接扩大资源范围。

续期操作只接受父 CA 为当前密钥新签发的 DER 证书。新证书必须保持主体、公钥、资源集合和发布 URI 不变，并且 `notAfter` 必须晚于当前证书。非自签 RC 仍需提供从 TA 到直接父 CA 的完整证书链，以及每级当前 CRL 和 Manifest：

```bash
rpki-ca renew-certificate \
  --dir data \
  --certificate renewed-child.cer \
  --tal trust-anchor.tal \
  --chain-certificate ta.cer \
  --chain-certificate parent.cer \
  --chain-crl ta.crl \
  --chain-crl parent.crl \
  --chain-manifest ta.mft \
  --chain-manifest parent.mft
```

HTTP 入口为 `POST /api/v1/ca/certificate-renewals`，字段为 `certificate_base64`、`tal_base64`、`chain_base64`、`crls_base64` 和 `manifests_base64`；后三项为数组。服务成功后返回 `204 No Content`。例如自签开发 TA 的请求体可生成如下：

```bash
jq -n \
  --arg certificate "$(base64 < renewed-ta.cer | tr -d '\n')" \
  --arg tal "$(base64 < trust-anchor.tal | tr -d '\n')" \
  '{certificate_base64: $certificate, tal_base64: $tal}' > renewal.json

curl --request POST http://localhost:3000/api/v1/ca/certificate-renewals \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header "Content-Type: application/json" \
  --data @renewal.json
```

续期会在同一个可恢复发布事务中替换当前 `<key-id>.cer` 并重签 `<key-id>.crl` 和 `<key-id>.mft`；同密钥、同资源条件下名称不变，已有 ROA/ASPA 保持有效。更换 CA 密钥不属于本操作，必须通过 RFC 6489 的双密钥 key-roll 状态机完成，目前尚未实现。
