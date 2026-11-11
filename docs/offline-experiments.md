# 离线对象实验

如果只安装 Docker，使用 [Docker 使用指南](docker-workflows.md)中的一次性实验和独立验签入口；下文保留本机 CLI 用法。

本流程面向直接读取签名对象文件的实验。每次新建临时开发 TA，签发输入指定的对象，导出公开材料并立即离线验证。成功后删除临时 CA，导出目录不包含私钥、CA 配置或 state.toml。再次运行会创建新的密钥、证书和签名；可复现的是输入和验证结果，不是 DER 字节。

## 一键运行

Linux 或 Git Bash，在项目根目录运行：

```bash
bash scripts/experiment.sh
# 自定义输入和输出；输出目录必须不存在
bash scripts/experiment.sh --request examples/experiment.json --output data/my-experiment
# 覆盖实验材料的 CRL/Manifest 有效期，例如 60 天
bash scripts/experiment.sh --valid-days 60 --output data/experiment-60-days
```

脚本默认执行 `cargo build --locked --offline` 并将构建产物放入项目的 `target/`，需要预先安装 Rust 并缓存依赖；首次使用可先运行 `cargo fetch --locked`。也可用 `--binary ./target/debug/rpki-ca`（Git Bash 下可用 `./target/debug/rpki-ca.exe`）指定已构建的程序，跳过构建。显式传入的相对路径以调用脚本时的目录为基准，路径含空格时加引号。无需 Docker、API 服务、rsync 服务或网络发布。

也可直接运行同一 CLI：

```bash
cargo run --locked --offline -- experiment --request examples/experiment.json --output data/my-experiment
cargo run --locked --offline -- verify-experiment --dir data/my-experiment
```

## 输入

`examples/experiment.json` 默认签发 TOA 和 SiSPI，包含独立的 CA IP/ASN 资源上限和对象定义。可修改它并保存为另一份 JSON。objects 支持当前实现的四种类型，每项采用 `{"kind":"类型","definition":{...}}`：

| kind | definition 示例 |
|---|---|
| roa | `{"asn":64498,"prefixes":[{"prefix":"192.0.2.0/24","max_length":26}]}` |
| aspa | `{"customer_asn":64496,"provider_asns":[64497]}` |
| toa | `{"asns":[64496,64497],"prefixes":["192.0.2.0/24"]}` |
| sispi | `{"asn":64496,"addresses":["192.0.2.1","2001:db8::1"]}` |

同一 ROA Origin ASN、ASPA Customer ASN、SiSPI AS ID 或相同 TOA 内容，在一个输入中只能定义一次。ROA 会先签发，TOA 会执行现有 ROA 重叠策略；完全覆盖时须显式提供 `roa_overlap_justification`。实验流程不跳过资源授权检查。

## 导出内容

```text
my-experiment/
  experiment.json       # 输入、文件与定义映射、SHA-256、生成版本、实验 Profile 信息
  trust-anchor.tal      # 固定本次开发 TA 的公钥
  verification.json     # 生成时验证结果和 Manifest nextUpdate 的 Unix 时间
  repository/
    <key-id>.cer
    <key-id>.crl
    <key-id>.mft
    <ee-key-id>.toa
    <ee-key-id>.sav
```

签名对象使用原发布文件名，以保持 EE SIA 与 Manifest 一致。实验程序直接读取 `repository/` 中的对象；EE 证书已经包含在对象的 CMS 内，无需私钥。

将整个目录复制到另一台安装了 rpki-ca 的机器后：

```bash
rpki-ca verify-experiment --dir my-experiment
# 如果实验方已独立保存可信 TAL，可明确指定，避免仅信任材料包自带的 TAL：
rpki-ca verify-experiment --dir my-experiment --tal /path/to/trusted-test.tal
```

验证会重新读取导出的字节，检查清单及哈希、TAL 公钥、CA、CRL、Manifest、对象 CMS 签名、EE Profile 和资源，并将实际内容与记录的输入比较。成功输出 JSON，失败退出码为非零；不会读取 CA 状态或下载任何 URL。`verification.json` 是历史记录，复验不信任其中的成功结果，也不修改材料包。

这是本项目实现的离线验证，不是独立第三方互操作认证。自带 TAL 仅建立隔离测试信任，SHA-256 清单不是可信来源证明；文件和 TAL 一起被替换时，须依赖实验方独立保存的 TAL/输入或外部可信摘要识别。

## 有效期

实验 JSON 支持 `ca` 部分配置名称、仓库 URI、CA 寿命和各对象 EE 寿命；省略时沿用默认值。完整字段及配置生效规则见 [CA 配置与信息查看](ca-configuration.md)。

实验包的 CRL/Manifest 默认有效期为 **30 天**，关闭随机偏移。输入 JSON 的 `valid_days` 可设置天数，省略时为 30；脚本和 `rpki-ca experiment` 均支持 `--valid-days N`，命令行优先于 JSON。实际生效值记录在导出的 `experiment.json` 中。旧包不会因默认值改变而延长有效期。

允许范围为 1～363 天；若自定义 CA 或对象 EE 寿命，还要求 `valid_days` 比 CA 寿命及本次涉及对象的 EE 寿命至少短一天。默认 EE 为 52 周、CA 为 365 天。CRL、Manifest 的 nextUpdate 和 Manifest EE 的 notAfter 一致。`verification.json` 中的 `publication_valid_until` 记录实际截止时间；普通对象 EE 的有效期独立保持原策略。

此设置仅应用于隔离实验 CA，在线 CA 的默认 24 小时加 0～4 小时随机偏移保持不变。

实验 JSON 不支持持久 CA TOML 中的 `rrdp_notification_uri`。需要持续向 Krill 发布时，先按 [Krill 接入指南](krill-publication.md) 创建持久 CA；`export-experiment` 和 `verify-experiment` 只处理本地公开材料，不发起远端同步。

如果实验仅解析对象内容，原文件可以继续使用；如果要求 `verify-experiment` 按当前时间完成信任链、吊销与发布集验证，则到期后必须提供新的有效材料。当前实验脚本会删除临时 CA 私钥，无法单独刷新旧包的 CRL/Manifest，因此这种情况下需要重新运行脚本生成整个新包。对象 EE 自身也有独立有效期。不应将历史 verification.json 当作当前有效性证明。

## 新对象 Profile 与接入

当前 TOA 采用代码中实现的 draft-qin-savnet-toa-02 和实验 OID `1.2.840.113549.1.9.16.1.999`；SiSPI 采用 draft-chen-sidrops-sispi-06 和实验 OID `1.2.840.113549.1.9.16.1.998`。这记录的是项目实现版本，并不声称是最新草案或正式分配。

新增类型时明确 ASN.1/DER、OID/版本/扩展名、字段规范化、EE IP/ASN 资源规则和验证拒绝条件，再接入 ObjectKind/ObjectDefinition、签名器、发布扩展名以及 `experiment::verify` 的内容验证分支。无需为本离线流程增加 HTTP API。

## 导出现有 CA

```bash
bash scripts/experiment.sh --ca /path/to/ca --output /path/to/new-bundle
# 或直接使用二进制
rpki-ca export-experiment --dir /path/to/ca --output /path/to/new-bundle
```

导出时持有 CA 状态锁，一次性读取已提交的状态与发布文件；不读取私钥、不续期、不重新签发。输出必须是 CA 目录之外的新目录。存在未完成发布事务时拒绝导出，应先恢复 CA。导出不改变源 CA 的配置、状态和发布字节。导入型 CA 的公开上级链、CRL、Manifest 验证上下文以 Base64 保存在材料清单中。

已有材料到期也可以导出：文件仍保留，`verification.json` 记录失败，命令以非零状态退出。`--valid-days` 只影响新建实验，不能延长快照的原有效期。

对于现有 CA 快照，报告中的 `publication_valid_until` 仅表示本地 Manifest 的 nextUpdate，并不代表整条信任链的最早失效时间；CA、CRL、对象 EE 或上级材料都可能更早失效，应以当前复验结果为准。

新包使用格式 v4，当前验证器继续读取 v1/v2/v3（字段名须符合当前 ASN 定义）；旧版验证器需要升级才能读取 v4。`experiment.json` 的 `files` 包含各发布文件的原 URI、SHA-256、大小、有效时间，以及适用的 AIA、CRL DP、Manifest/Signed Object SIA、CMS 内容 OID、EE 有效期和 `decoded`。时间为 Unix 秒；CRL/Manifest 的 `valid_from/valid_until` 是 thisUpdate/nextUpdate。上级验证材料保存在 `parent_context`，不包含在本地 `files` 清单中。原 URI 仅用于关联，不要求在线下载。

`files.<文件名>.decoded` 从实际 DER 文件解码，覆盖 CA 证书、CRL、Manifest、ROA、ASPA、TOA、SiSPI，与 API 对象详情共用解码器。签名对象的 `decoded.eContent` 保存实际 ASN、前缀、提供商或 Agent 地址等载荷；`decoded.cms` 保存 CMS 结构和内嵌 EE 证书信息。`objects.<文件名>.definition` 保留预期输入，不用它代替实际解码内容。v4 复验重新从文件解码并比较：缺失或篡改 `decoded` 返回 `metadata` 错误。只解码不会验证签名，完整复验仍执行原有证书链、吊销、资源及载荷检查。

### 实验元数据

新建实验与现有 CA 快照共用以下字段：

| 字段 | 内容与来源 |
|---|---|
| `profiles` | 本包实际包含的对象类型及当前实现的 Profile 文档版本、内容 OID；ROA、ASPA、TOA、SiSPI 都覆盖 |
| `ca_metadata.certificate` | 从 CA DER 解析的 Subject、Issuer、序列号、SKI、证书 SHA-256、资源、发布 URI、有效期 |
| `ca_metadata.configuration` | 导出时的公开配置摘要：本地名称、URI、开发资源及有效期策略；显式白名单，不含私钥或本地路径 |
| `parent_materials` | 上级证书、CRL、Manifest 的类型、原数组位置、SHA-256、大小、有效期；Manifest 还包含 EE 证书详情 |

`parent_materials[].source` 如 `parent_context.crls_base64[0]`，指向包内现有 Base64 字节，不是新文件或下载地址。证书使用 `not_before/not_after`，CRL/Manifest 使用 `this_update/next_update`；对应的 `*_utc` 为便于阅读的 RFC 3339 UTC 时间。自建 TA 无上级材料，数组为空；继承资源以继承标志标明，显式值为 null。

v3/v4 复验从原始 DER 重建 CA 和上级材料摘要，并检查 Profile 信息；缺失或不一致返回 `metadata` 错误。新建实验还对照请求检查配置摘要。快照配置仅是导出时的记录，无法从证书还原本地名称或历史签发策略，也不表示已有证书已按当前配置重新签发。`profiles` 描述导出程序所实现的版本，不是外部认证或历史签发软件版本证明。

这些 JSON 字段本身没有数字签名。复验能发现与材料不一致的内容，但不能证明快照配置记录的真实性；仍需独立可信 TAL 或外部可信摘要确认来源。不会复制完整 `ca.toml`、状态库或私钥。

复验失败也在标准输出提供 JSON：`error.code` 表示失败阶段，`error.object` 尽可能指出文件，`error.message` 说明原因。代码包括 `input`、`inventory`、`sha256`、`decode`、`not_yet_valid`、`expired`、`trust_path`、`publication_set`、`object_profile_payload`、`metadata`。一次报告首个失败；上级链问题归入 `trust_path`。复验不会覆盖原历史报告，可自行重定向保存。

## 独立交叉检查

```bash
bash scripts/verify-experiment-independent.sh --dir /path/to/bundle
# 可用 --openssl /path/to/openssl 指定 OpenSSL；PYTHON 环境变量指定 Python 3
```

此入口使用 Python 标准库检查目录及 SHA-256，并调用 OpenSSL 独立检查所有签名对象与 Manifest 的 CMS 签名。它不依赖本项目的 Rust 验证代码。输出显式标记 `scope` 和 `limitations`：**不检查信任链、吊销、时间、RFC 3779 资源、对象 Profile 或预期载荷**，因此必须配合 `verify-experiment` 使用，不能当作完整第三方 RPKI 验证或互操作认证。OpenSSL 使用 `cms -verify -noverify`，其中 `-noverify` 只跳过签名者证书链验证，仍检查 CMS 签名。

```bash
python3 tests/test_independent_verify.py
```

独立检查测试生成实际 CMS，验证正常签名、文件篡改、重算清单后仍被密码学验签拒绝、缺失文件。

## Rust 回归测试

```bash
cargo test --offline experiment::tests
```

包含四类对象导出与迁移后的无私钥验证、拒绝覆盖已有输出、空输入/重复身份、篡改文件、篡改清单后仍被 Manifest 拒绝、错误预期内容、错误 TAL、缺失/额外文件；TOA/SiSPI 还直接测试错误 CMS 签名、错误内容 OID、IP/ASN 越权拒签。现有 Profile 测试继续覆盖非法 DER、空集合和排序等约束。
