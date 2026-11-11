# rpki-ca

一个用于**创建单 CA、签发 RPKI 签名对象并导出实验文件**的 Rust 工具。当前支持 ROA、ASPA、实验性 TOA 和 SiSPI；签发时自动维护对象 EE 证书、CRL、Manifest 和本地发布仓库。

本项目的主要使用流程是：

```text
配置资源与有效期 → 创建 CA → 签发对象 → 导出对象或材料包 → 在实验中解析或离线验证
```

本文默认使用 Docker 执行 CLI，流程 A 和流程 B 无需启动 HTTP API；需要验证服务调用链时可选择 Compose/API 批量流程。开发 CA 是隔离实验用的自签 Trust Anchor，不属于公共 RPKI 信任体系。当前重点是开发与协议实验；远程仓库可按需使用 [Krill 发布同步](docs/krill-publication.md)。

## 选择使用方式

| 你的目的 | 使用方式 | 最终得到什么 |
|---|---|---|
| 只需要一批签好的对象文件 | **流程 A：一次性实验** | 公开材料包；临时 CA 私钥自动删除 |
| 需要反复签发、更新或撤回对象 | **流程 B：保留 CA** | 持久 CA 目录、单对象副本，以及可随时导出的公开快照 |
| 希望先启动服务，再通过 HTTP API 批量提交同一份实验 JSON | **Compose/API 批量流程** | 持久容器与 CA，以及经过离线验证的公开快照 |
| 已有自己的资源证书和匹配私钥 | [导入 CA](docs/import-ca.md)，然后按流程 B 签发 | 在所获资源范围内签发的对象 |
| 希望验证器通过 RRDP/rsync 拉取对象 | [Krill 发布仓库接入](docs/krill-publication.md) | 独立仓库中的公开发布集；使用持久 CA 并显式同步 |

- [准备环境](#准备环境)
- [流程 A：一次性创建并导出实验对象](#流程-a一次性创建并导出实验对象)
- [Compose/API 批量签发与导出](#composeapi-批量签发与导出)
- [流程 B：保留 CA，逐个签发并导出](#流程-b保留-ca逐个签发并导出)
- [导出后如何使用与验证](#导出后如何使用与验证)
- [有效期、刷新与重新导出](#有效期刷新与重新导出)
- [通过 Krill 发布到远程仓库](#通过-krill-发布到远程仓库)
- [常见问题](#常见问题)
- [其他入口与开发文档](#其他入口与开发文档)

## 准备环境

**宿主机只需要 Docker 和 Docker Compose，不需要安装 Rust/Cargo、平台编译工具链、Python 或 OpenSSL。** 所有命令在项目根目录的 Linux Bash 或 Windows Git Bash 中执行，Docker 使用 Linux 容器。

拿到源码后构建镜像，编译在 Docker 内完成：

```bash
docker build -f docker/Dockerfile -t rpki-ca:0.1.0 .
docker build --target tools -f docker/Dockerfile -t rpki-ca-tools:local .
bash scripts/rpki-ca-docker.sh --help
```

第一条构建运行镜像，第二条构建包含 Python/OpenSSL 的辅助工具镜像。首次构建需要联网下载基础镜像和依赖；镜像已构建后，可直接运行下文各流程，无需重复构建。修改源码后才需要重新构建。

`bash scripts/rpki-ca-docker.sh` 将项目目录挂载到容器的 `/work` 并直接执行 CA 命令。相对路径以项目根目录为准；CA、publisher 身份和导出文件保存在宿主机的挂载目录内，不随临时容器退出而删除。输入和输出应放在项目目录内，绝对路径应使用容器路径。

Compose/API 批量脚本会自动构建运行镜像和工具镜像，只需先配置 `docker/.env` 中的 `API_TOKEN`。完整的镜像、路径、网络和 Krill TLS 说明见 [Docker 使用指南](docs/docker-workflows.md)。Krill 还需配置注册信息、可达的仓库地址和 TLS，容器内的 `localhost` 指向该容器自身。

## 流程 A：一次性创建并导出实验对象

适合只需要对象文件、无需保留签发 CA 的实验。

### 1. 用默认输入生成一份材料包

```bash
bash scripts/rpki-ca-docker.sh experiment \
  --request examples/experiment.json \
  --output ./data/experiments/run-001
```

默认输入包含一个 TOA 和一个 SiSPI。脚本依次完成：

1. 检查输入、资源和有效期配置。
2. 在临时目录创建自签实验 CA。
3. 签发请求中的对象，同步生成 CRL 和 Manifest。
4. 导出公开材料，使用导出后的字节执行离线验证。
5. 验证成功后保存材料包，并删除临时 CA 和私钥。

成功时输出 `status: "valid"`。`--output` 必须指定不存在的新目录；再次运行请换成 `run-002` 等名称。

### 2. 自定义对象和 CA

可以复制 [examples/experiment.json](examples/experiment.json) 后修改。完整四类对象示例已保存在 [examples/experiment-all.json](examples/experiment-all.json)，可直接运行：

```bash
bash scripts/rpki-ca-docker.sh experiment \
  --request examples/experiment-all.json \
  --output ./data/experiments/all-objects-001
```

下面是一份可自定义的四类对象请求：

```bash
cat > experiment.json <<'JSON'
{
  "ca": {
    "name": "my-object-experiment",
    "repository_uri": "rsync://localhost/experiment/",
    "development_ca_validity_days": 365,
    "ca_renew_before_days": 30,
    "roa_valid_weeks": 52,
    "aspa_valid_weeks": 52,
    "toa_valid_weeks": 52,
    "sispi_valid_weeks": 52
  },
  "valid_days": 30,
  "resources": ["192.0.2.0/24", "2001:db8::/48"],
  "asn_resources": [64496],
  "objects": [
    {
      "kind": "roa",
      "definition": {
        "asn": 64496,
        "prefixes": [{"prefix": "192.0.2.0/24", "max_length": 24}]
      }
    },
    {
      "kind": "aspa",
      "definition": {"customer_asn": 64496, "provider_asns": [64497, 64498]}
    },
    {
      "kind": "toa",
      "definition": {
        "asns": [64496, 64497],
        "prefixes": ["192.0.2.0/24", "2001:db8::/48"]
      }
    },
    {
      "kind": "sispi",
      "definition": {"asn": 64496, "addresses": ["192.0.2.1", "2001:db8::1"]}
    }
  ]
}
JSON

bash scripts/rpki-ca-docker.sh experiment \
  --request ./experiment.json \
  --output ./data/experiments/four-objects-001
```

| 字段 | 作用 |
|---|---|
| `ca.name` | 本地实验名称；不改变证书 Subject，Subject 仍由公钥生成 |
| `ca.repository_uri` | 写入证书及相关材料的仓库基础 URI；配置它不会启动 rsync 服务 |
| `ca.development_ca_validity_days` | 新建 CA 证书寿命 |
| `ca.*_valid_weeks` | 各类对象 EE 证书的寿命策略 |
| `valid_days` | 本次实验的 CRL/Manifest 有效天数，默认 30，无随机偏移 |
| `resources` | 实验 CA 持有的 IPv4/IPv6 资源 |
| `asn_resources` | 实验 CA 持有的 ASN 资源 |
| `objects` | 要签发的对象定义；可以只保留需要的类型 |

`ca` 及其中字段可以省略。`valid_days` 范围为 1～363，且必须比 CA 及本次所签对象的 EE 寿命至少短一天。命令行 `--valid-days 60` 可以覆盖 JSON 中的天数；该参数不改变对象 EE 自身的寿命策略。更多约束见 [CA 配置](docs/ca-configuration.md)。

每次运行都会新建密钥和证书，因此相同 JSON 不保证生成相同文件名、序列号或签名字节；可比较的是规范化后的对象内容。

### 3. 找到签名对象文件

生成的目录结构如下，文件名以实际输出为准：

```text
four-objects-001/
├── experiment.json       # 输入、对象清单、Profile、CA 与上级材料元数据
├── trust-anchor.tal      # 此材料包使用的信任锚定位信息
├── verification.json     # 导出时的验证结果
└── repository/
    ├── <ca-key-id>.cer    # CA 证书
    ├── <ca-key-id>.crl    # 吊销列表
    ├── <ca-key-id>.mft    # Manifest
    ├── <object-name>.roa  # ROA
    ├── <object-name>.asa  # ASPA，扩展名是 .asa
    ├── <object-name>.toa  # TOA
    └── <object-name>.sav  # SiSPI，扩展名是 .sav
```

对象是 DER 编码的 CMS 文件，内部已包含对应 EE 证书。只做对象解析或将字节交给实验程序时，读取 `repository/` 下所需扩展名的文件即可。若需要验证信任链、吊销与发布集，请保留整个材料包及原文件名。

材料包不包含 CA 私钥、`state.toml` 或完整 `ca.toml`，不能将它当作可继续签发的 CA 目录。

## Compose/API 批量签发与导出

如果实验要验证“先部署服务，再通过 HTTP 请求签发”的完整路径，可在 Linux Bash 或 Windows Git Bash 下使用 `scripts/experiment-compose.sh`。它在工具容器内转换 JSON、检查已有 CA 配置并发送 HTTP 请求，宿主机不需要 Rust、Python 或 `jq`。其他容器流程见 [Docker 使用指南](docs/docker-workflows.md)。

先准备 Compose 的基础环境，其中 `API_TOKEN` 必须设置：

```bash
cp docker/.env.example docker/.env
# 编辑 docker/.env，至少把 API_TOKEN 改成自己的长随机值。
```

然后用与一次性流程相同的请求文件运行：

```bash
bash scripts/experiment-compose.sh \
  --request ./experiment.json \
  --output ./data/experiments/compose-001
```

脚本按以下顺序执行：

1. 从 `experiment.json` 读取 CA 名称、资源、对象有效期和 `valid_days` 发布窗口（省略时为 30 天）。
2. 执行 `docker compose up -d --build`，等待 `/healthz` 可用。
3. 将 ROA、ASPA、TOA、SiSPI 定义转换为各接口的 `{added, removed}` 增量请求并提交。
4. 在容器内运行 `export-experiment`，对当前公开仓库执行完整离线复验。
5. 把不含私钥的快照移到 `--output`；默认继续运行服务并保留 CA。

默认持久数据在 `data/compose-experiment/`，Compose 项目名为 `rpki-ca-experiment`，API 地址为 `http://127.0.0.1:3000`。后续可以再次运行脚本，或直接调用 HTTP API 继续签发。重复的 ROA 配置会先查询后跳过；其他三类对象由服务端按目标状态幂等处理。

已有 CA 不会因 JSON 改动而重新初始化。脚本会先比较名称、仓库 URI、资源和关键有效期；不一致时停止并要求选择新的数据目录。例如，创建另一套独立 CA：

```bash
bash scripts/experiment-compose.sh \
  --request ./experiment.json \
  --data-dir ./data/compose-ca-002 \
  --project-name rpki-ca-experiment-002 \
  --api-port 3001 \
  --output ./data/experiments/compose-002
```

复用持久 CA 时，导出包包含该 CA 当前的**全部**已签对象，而不只包含本次 JSON 新增的对象。若只想执行完后停止容器，可加 `--down-after`；CA 数据仍会保留。更多参数见：

```bash
bash scripts/experiment-compose.sh --help
```

## 流程 B：保留 CA，逐个签发并导出

适合需要持续签发、更新输入、刷新发布材料的实验。下面使用同一个 CA 依次签发四类对象。

### 1. 检查配置并创建 CA

```bash
bash scripts/rpki-ca-docker.sh check-config --config examples/ca.toml
bash scripts/rpki-ca-docker.sh init --dir ./data/my-ca --config examples/ca.toml
bash scripts/rpki-ca-docker.sh ca-info --dir ./data/my-ca
```

初始化目录必须不存在或为空；已有 CA 直接用于后续签发，不要再次运行 `init`。

[examples/ca.toml](examples/ca.toml) 已配置 IP 资源 `192.0.2.0/24`、`2001:db8::/48` 和 ASN `64496`，以及 30 天的 CRL/Manifest 窗口，足以运行下面所有示例。可先复制并修改 TOML，再传入 `--config`。`--config` 与显式 CA 参数互斥，但可与 `--dir` 共用。

`ca-info` 无需私钥即可查看配置、实际证书 Subject/资源/URI、有效期和不一致提示；它是信息查看，不代替密码学验证。

CA 目录包含需要保留的签发状态：

```text
data/my-ca/
├── ca.toml       # 配置
├── ca.key        # CA 私钥，后续签发需要
├── state.toml    # 序列号、对象和吊销等状态
├── state.lock    # 并发访问锁
└── repository/  # CA 管理的实际发布文件
```

请保留整个 CA 目录用于后续操作；分发实验材料时使用导出命令，不直接分发这个目录。

### 2. 签发并导出单个 ROA

```bash
bash scripts/rpki-ca-docker.sh sign-roa \
  --dir ./data/my-ca \
  --asn 64496 \
  --prefix 192.0.2.0/24 \
  --prefix '2001:db8::/48,48' \
  --output ./exports/roa-64496.roa
```

`--prefix` 可以重复，格式为 `PREFIX` 或 `PREFIX,MAX_LENGTH`。省略最大长度时，只允许给出的前缀长度。Origin ASN 是授权对象，不要求 CA 持有该 ASN；IP 前缀必须由 CA 证书覆盖。

也可以用 `sign-roa --request request.json` 代替 `--asn/--prefix`。请求结构为 `{"asn":64496,"prefixes":[{"prefix":"192.0.2.0/24","max_length":24}]}`。

ROA 以授权集合管理，同 ASN 的授权合并为一个发布对象。重复加入已有授权会被拒绝；增删授权使用 `update-roas --delta`，查询使用 `list-roas`，而不是直接修改仓库文件。

### 3. 签发并导出 ASPA

```bash
bash scripts/rpki-ca-docker.sh sign-aspa \
  --dir ./data/my-ca \
  --customer-asn 64496 \
  --provider-asn 64497 \
  --provider-asn 64498 \
  --output ./exports/aspa-64496.asa
```

CA 必须持有 Customer ASN `64496`，不要求持有 Provider ASN。Provider 列表不能为空，不能包含 Customer 本身；当前实现会排序并去重。ASPA 的文件扩展名为 `.asa`。

### 4. 签发并导出 TOA

```bash
bash scripts/rpki-ca-docker.sh sign-toa \
  --dir ./data/my-ca \
  --asn 64496 \
  --asn 64497 \
  --prefix 192.0.2.0/24 \
  --prefix 2001:db8::/48 \
  --output ./exports/traffic-origin.toa
```

TOA 的 IP 前缀必须由 CA 覆盖；其中的 ASN 集合不是 CA 的 ASN 资源清单。TOA EE 使用 IP 资源。

签发会检查 TOA 的 `(ASN, 前缀)` 组合与已有 ROA 的覆盖关系。上例还包含没有对应 ROA 的 ASN `64497`，属于部分重叠，可继续签发。若全部组合已被 ROA 覆盖，必须提供非空的 `--roa-overlap-justification '实验用途说明'`；JSON 请求中的对应字段放在 TOA 的 `definition` 内。部分重叠可能输出 `ADVISORY`，不表示签发失败。

### 5. 签发并导出 SiSPI

```bash
bash scripts/rpki-ca-docker.sh sign-sispi \
  --dir ./data/my-ca \
  --asn 64496 \
  --address 192.0.2.1 \
  --address 2001:db8::1 \
  --output ./exports/agent-64496.sav
```

CA 必须持有 `asn` 对应的 ASN。这里的地址是 SAVNET Agent 地址，不是 EE 证书中授权的 IP 资源；应填写地址而非前缀。SiSPI 的扩展名为 `.sav`。

SiSPI 的 JSON、CA 状态、实验记录及 API 解码字段统一为 `asn`，签发、验证和撤回命令统一使用 `--asn`。不提供旧字段或旧参数的兼容入口；签名对象的 DER 编码保持不变。

### 6. 理解单文件导出与真实发布名称

每次 `sign-*` 都会先完成 CA 的本地签发/发布，再把对象字节写到 `--output`。终端会同时显示：

```text
... published as repository/<实际文件名>; exported to ./exports/<副本名>
```

`exports/` 中的名称是便于实验使用的副本名；真正写入 EE SIA、Manifest 和状态的发布文件名由 CA 管理。`--output` 不能放进 CA 的 `repository/`。示例使用 CA 目录之外的 `exports/`，避免与 CA 状态混放。

**单对象输出路径已有文件时可能被覆盖；完整材料包的输出目录则不允许覆盖。** 不要为了统一名称而重命名材料包的 `repository/` 文件。使用完整验证流程时，应以真实发布名和对应 Manifest 为准。

### 7. 导出完整公开快照

四类对象签完后，把当前 CA 的已提交发布状态导出为一个材料包：

```bash
bash scripts/rpki-ca-docker.sh export-experiment \
  --dir ./data/my-ca \
  --output ./data/experiments/my-ca-snapshot-001
```

输出必须是 CA 目录之外的新目录。

快照导出会持有 CA 状态锁读取文件和清单，不需要私钥，不重新签发，也不延长有效期；不支持通过 `--valid-days` 修改现有材料的有效期。有未完成发布事务时拒绝导出，应先完成 CA 恢复。

如果材料已经过期，快照仍可保存用于分析，但 `verification.json` 会记录验证失败，命令返回非零状态。这与一次性实验“先验证通过再提交新包”的行为不同。

## 导出后如何使用与验证

### 按实验目的选择材料

| 实验内容 | 应使用的材料 |
|---|---|
| 读取 ASN、前缀、Agent 地址或分析 ASN.1/CMS 编码 | 对应 `.roa` / `.asa` / `.toa` / `.sav` 文件 |
| 验证签名对象及本地发布集 | 整个导出包，包括 CA、CRL、Manifest 和 TAL |
| 比较不同实验的输入和输出 | 对象内容及 `experiment.json`；不要只比较随机生成的签名字节 |
| 再签发或刷新 | 原来的持久 CA 目录，公开材料包不能用于签发 |

### 用本项目执行完整离线复验

将整个材料包复制到实验机器，在该机器准备同版本 Docker 镜像，并把材料包放入项目挂载目录，然后执行：

```bash
bash scripts/rpki-ca-docker.sh verify-experiment --dir ./data/experiments/my-ca-snapshot-001

# 如已通过独立可信渠道保存 TAL，可以明确指定：
bash scripts/rpki-ca-docker.sh verify-experiment \
  --dir ./data/experiments/my-ca-snapshot-001 \
  --tal ./data/trusted.tal
```

复验不读取原 CA 目录、不需要私钥、不联网。它重新检查文件清单与哈希、TAL/证书路径、当前时间有效性、CRL 吊销状态、Manifest、CMS 签名、EE Profile/资源，以及对象内容与包内预期输入是否一致。导入型 CA 还使用包内保存的上级证书、CRL 和 Manifest。

成功输出 `status: "valid"`；失败返回非零退出码，并在 JSON 中提供 `error.code`、`error.object` 和原因。包内 `verification.json` 是导出时的历史记录，复验不会直接信任它，也不会覆盖它。

默认信任包内 TAL 只说明该实验包在其自带信任锚下成立；不能证明它属于公共 RPKI。离线验证也无法获知导出后新发生的吊销或仓库更新。

### 用 OpenSSL 交叉检查

```bash
bash scripts/verify-experiment-docker.sh \
  --dir ./data/experiments/my-ca-snapshot-001
```

此脚本在工具容器中使用 Python 检查清单/哈希，并调用 OpenSSL 检查对象与 Manifest 的 CMS 签名；宿主机无需安装这些工具。

它**不检查**完整证书路径、吊销、有效期、资源授权或对象预期内容，不能代替上一节的主验证器；输出会明确给出检查范围。

### 材料包中的实验记录

新包使用格式 v4，当前验证器也支持 v1/v2/v3（字段名须符合当前 ASN 定义）；旧版验证器需升级后才能读取 v4。

| `experiment.json` 字段 | 内容 |
|---|---|
| `source` / `request` | 新建实验或现有 CA 快照；新建实验保存请求，快照的 `request` 为 null |
| `objects` / `profiles` | 实际发布名与对象定义、当前实现的 Profile 版本和 OID |
| `files` / `repository_sha256` | URI、哈希、大小、有效期、EE 与 CMS 信息 |
| `files.<文件名>.decoded` | 从该文件 DER 字节解码的实际内容，与 API 对象详情的 `decoded` 使用同一解码器 |
| `ca_metadata.certificate` | 从证书解析的 CA Subject、Issuer、SKI、资源、URI、有效期 |
| `ca_metadata.configuration` | 导出时公开配置摘要，与证书实际字段分开 |
| `parent_context` / `parent_materials` | 上级验证字节与可读有效期摘要；自建 TA 没有上级材料 |

v4 为仓库中的每个文件保存解码结果，包括 CA 证书、CRL、Manifest 及四类签名对象。签名对象的 `decoded.eContent` 是实际载荷，`decoded.cms` 提供 CMS 结构和内嵌 EE 证书信息；`objects` 中的 `definition` 仍是预期对象定义，两者分别保留。

复验会重新解码原始文件并核对 `decoded`；v4 缺失或修改解码结果会返回 `metadata` 错误。配置摘要本身没有数字签名，不代表历史对象按当前配置签发，也不能单独证明材料来源。完整说明见 [离线对象实验](docs/offline-experiments.md)。

## 有效期、刷新与重新导出

| 创建方式 | CRL/Manifest 初始策略 |
|---|---|
| 一次性 `experiment` | 默认 30 天，无随机偏移，可用 `valid_days` 或 `--valid-days` 调整 |
| 本文 `init --config examples/ca.toml` | 示例文件显式设为 720 小时，即 30 天，无随机偏移 |
| 不提供配置的普通 `init` | 默认 24 小时，加 0～4 小时随机偏移 |
| `export-experiment` 快照 | 保留原材料时间，不重新计时 |

默认新建 CA 证书寿命为 365 天，对象 EE 默认 52 周且不会超过 CA 到期时间。修改配置不会延长已签出的对象。报告里的 `publication_valid_until` 是本地 Manifest 的截止时间，不一定是整个证书链的最早失效时间。

保留 CA 的情况下，可以刷新发布材料，再导出一个新快照：

```bash
bash scripts/rpki-ca-docker.sh certificate-status --dir ./data/my-ca
bash scripts/rpki-ca-docker.sh refresh --dir ./data/my-ca
bash scripts/rpki-ca-docker.sh export-experiment \
  --dir ./data/my-ca \
  --output ./data/experiments/my-ca-snapshot-002
```

`refresh` 更新 CRL/Manifest，不是 CA 换证或对象 EE 续期；CA、对象 EE 和导入链材料也必须有效。按实际 `nextUpdate` 安排刷新。一次性实验已删除私钥，无法刷新旧包，需要重新运行流程 A 生成新包。

到期的文件仍可用于纯解析实验，但不能再声称它们通过了当前时间的完整验证。更换证书和更新上级验证上下文见 [CA 生命周期](docs/ca-lifecycle.md)与[导入 CA](docs/import-ca.md)。

## 通过 Krill 发布到远程仓库

需要在线仓库时，先按 [Krill 接入指南](docs/krill-publication.md) 部署发布服务、注册独立 BPKI 身份，再使用返回的发布地址配置持久 CA。原有签发和本地导出流程继续使用本地仓库；远程同步通过 `publisher` CLI 显式执行。

例如，已按指南创建 `data/krill/ca` 和 `data/krill/publisher` 后：

```bash
bash scripts/rpki-ca-docker.sh publisher sync \
  --publisher-dir data/krill/publisher --dir data/krill/ca \
  --tls-ca docker/krill/tls/ca.crt --dry-run

bash scripts/rpki-ca-docker.sh publisher sync \
  --publisher-dir data/krill/publisher --dir data/krill/ca \
  --tls-ca docker/krill/tls/ca.crt
```

签发、撤回、刷新或换证后重新同步。每个 CA 使用独立 publisher；本地写入成功与远端同步成功是两个状态，HTTP API 和 Compose 实验脚本不会自动发布到 Krill。一次性实验包已删除私钥，后续发布应使用持久 CA。自签 CA 仍需向验证器提供可信 TAL，TOA/SiSPI 仍需相应实验解析支持。

## 常见问题

| 现象 | 处理方式 |
|---|---|
| Docker 镜像尚未构建 | 执行准备环境中的镜像构建命令；使用 `--no-build` 前确保运行和工具镜像均已存在 |
| CA 或材料包输出目录已存在 | 使用已有 CA 继续签发；新建 CA/材料包请选择新目录 |
| ASPA/SiSPI 报 ASN 越权 | 检查 CA 实际证书是否持有 Customer ASN / AS ID；仅修改配置不会增加证书资源 |
| ROA/TOA 报 IP 越权 | 检查前缀是否在 CA 证书资源内，以及是否有主机位 |
| 重复提交 ROA 授权被拒绝 | 用 `list-roas` 检查当前集合，再通过 `update-roas` 增删 |
| TOA 因 ROA 全覆盖被拒绝 | 提供具体的重叠例外理由，或调整实验输入 |
| 验证返回 `not_yet_valid` | 检查系统时间；连续发布的时间戳可能短暂领先，稍后重试 |
| 验证返回 `expired` | 检查具体到期文件，刷新/更新相应材料后重新导出，或重新生成实验包 |
| 单对象副本写入失败 | 签发可能已经完成，先检查 CA 当前发布状态，避免直接重复提交同一请求 |
| 快照导出返回非零但目录已生成 | 查看目录中的 `verification.json`，导出的原材料可能已过期或验证失败 |
| 想让证书显示 CA 的可读名称 | `name` 只是本地标签；当前 Subject 按公钥生成，不提供自定义 CN |
| 本地签发成功但 Krill 没有更新 | 使用已注册 publisher 执行 `publisher sync`；检查发布地址是否匹配、TLS 信任和远端响应 |

## 其他入口与开发文档

本项目实现的对象版本如下，表示代码所支持的版本，不声称是最新标准或草案：

| 对象 | 扩展名 | 实现的 Profile |
|---|---|---|
| ROA | `.roa` | RFC 9582 |
| ASPA | `.asa` | draft-ietf-sidrops-aspa-profile-29 |
| TOA | `.toa` | draft-qin-savnet-toa-02；实验 OID `1.2.840.113549.1.9.16.1.999` |
| SiSPI | `.sav` | draft-chen-sidrops-sispi-06；实验 OID `1.2.840.113549.1.9.16.1.998` |

需要常驻接口时可使用 `serve` 或 Docker Compose，CLI 与 HTTP API 共用 CA 核心。详细内容单独维护：

- [CA 配置与信息查看](docs/ca-configuration.md)
- [离线实验、验证范围与元数据](docs/offline-experiments.md)
- [HTTP API、对象查询与撤回](docs/http-api.md)
- [导入资源证书与更新上级材料](docs/import-ca.md)
- [CA 生命周期与换证](docs/ca-lifecycle.md)
- [Docker Compose](docs/docker-compose.md)
- [Krill 发布仓库功能与接入指南](docs/krill-publication.md)
- [架构与调用链](docs/architecture.md)

`src/main.rs` 是唯一 crate 入口；`cli`、`api` 为接口层，`application` 编排用例，`ca` 处理签发，`infrastructure` 管理存储和签名，`validation` 负责验证，`experiment` 负责实验包。默认提供本地发布仓库；可通过新增 `publisher` 命令显式同步到 [Krill Publication Server](docs/krill-publication.md)，不影响原有本地和离线流程。

本机源码开发检查单独列在 [开发文档](docs/development.md)，不属于 Docker 运行的准备步骤。

Docker 端到端测试需要 Docker Compose，输入集中在 `tests/e2e/config.sh`：

```bash
bash tests/e2e/0_run.sh
# 也可单独指定 roa、aspa、toa 或 sispi：
bash tests/e2e/0_run.sh toa
```

端到端脚本创建并清理专用测试环境，默认使用宿主机端口 3100，可用 `RPKI_CA_E2E_PORT` 覆盖。它会签发、下载并验证对象，适合修改 HTTP API 后检查完整服务流程。
