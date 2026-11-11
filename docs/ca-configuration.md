# CA 配置与信息查看

## 从配置文件创建 CA

```bash
rpki-ca check-config --config examples/ca.toml
rpki-ca init --dir ./my-ca --config examples/ca.toml
rpki-ca ca-info --dir ./my-ca
```

配置文件采用 TOML，与生成的 `ca.toml` 使用相同字段。省略字段使用默认值，未知字段（包括 `[timing]` 中的拼写错误）报错。`check-config` 检查开发 CA 配置并输出展开默认值后的 JSON，不创建目录或密钥。`init --config` 可以与 `--dir` 共用，但不能与显式 `--name`、`--repository-uri`、资源或时间参数混用；不传 `--config` 时原有 CLI 用法保持有效。

`certificate_uri` 在开发 CA 初始化时按新公钥和仓库 URI 自动生成。导入 CA 时必须使用上级分配的真实证书 URI，证书资源由导入证书及父链决定。

示例见 [examples/ca.toml](../examples/ca.toml)。`name` 是本地名称，不是证书 Subject；Subject 继续由公钥生成。配置仓库 URI 不会启动 rsync 或 HTTP 服务。

## TOML 字段与默认值

| 字段 | 默认值与用途 |
|---|---|
| `name` | `development-ca`，本地标签 |
| `repository_uri` | `rsync://localhost/rpki/`，写入 CA 发布地址 |
| `certificate_uri` | 空字符串；开发 CA 初始化时自动生成，导入时必须提供真实 URI |
| `rrdp_notification_uri` | 省略，启用 RRDP 时设置 HTTPS notification URI |
| `development_ca_validity_days` | `365`，新建开发 CA 证书寿命 |
| `ca_renew_before_days` | `30`，到期预警窗口 |
| `development_resources` | `192.0.2.0/24`、`2001:db8::/48`，新建开发 CA 的 IP 资源 |
| `development_asns` | 空数组；ASPA/SiSPI 实验需配置对应 Customer ASN/AS ID |
| `[timing]` 的 `roa_valid_weeks`、`aspa_valid_weeks`、`toa_valid_weeks`、`sispi_valid_weeks` | 均为 `52`，对象 EE 寿命 |
| `[timing].toa_review_days` | `90`，TOA 运行复核间隔 |
| `[timing].publish_next_hours` | `24`，CRL/Manifest 基础发布窗口 |
| `[timing].publish_next_jitter_hours` | `4`，发布窗口随机偏移上限 |
| `[timing].publish_hours_before_next` | `8`，提前刷新窗口 |

表中的 `[timing].字段` 表示在 TOML 的 `[timing]` 区块内设置字段，不是文件中的完整键名。[示例配置](../examples/ca.toml) 显式使用 720 小时、无随机偏移，与普通初始化的默认值不同。

## 一键实验的 CA 配置

`examples/experiment.json` 的 `ca` 部分支持：

```json
{
  "ca": {
    "name": "my-experiment",
    "repository_uri": "rsync://example.test/lab/",
    "development_ca_validity_days": 365,
    "ca_renew_before_days": 30,
    "roa_valid_weeks": 52,
    "aspa_valid_weeks": 52,
    "toa_valid_weeks": 52,
    "sispi_valid_weeks": 52
  }
}
```

此片段需要与原有 `resources`、`asn_resources`、`objects` 合并。`ca` 及其中字段均可省略，旧请求继续有效。资源只在顶层配置，避免两处定义冲突。CRL/Manifest 继续由顶层 `valid_days` 控制，默认 30 天，无随机偏移；脚本 `--valid-days` 优先于 JSON。TAL 和材料清单 URI 根据实际 CA 配置生成。

实验 JSON 的 `ca` 使用单独的字段集合，不支持 TOML 的 `rrdp_notification_uri`、`certificate_uri` 或整个 `[timing]` 结构。接入 Krill 使用持久 CA 的 TOML 配置。

```bash
bash scripts/experiment.sh --request ./experiment.json --output ./bundle
```

## 配置校验

以下上限是本项目的实现策略，不是 RFC 规定：CA 寿命 1～36500 天；续期提醒 1～36500 天；对象 EE 有效期 1～520 周；TOA 复核 1～3650 天；CRL/Manifest 基础窗口 2～87600 小时。

开发 CA 的续期提醒必须短于 CA 寿命，发布窗口加随机偏移也必须短于 CA 寿命；至少配置一种 IP/ASN 资源。提前刷新时间必须大于零且小于基础窗口，随机偏移不超过基础窗口的一半。名称不能空白或包含控制字符；URI 必须可解析为 rsync URI，证书 URI 必须指向 `.cer`；资源前缀不能有主机位，不能出现完全重复的 IP/ASN 项。

一键实验仍限制 `valid_days` 为 1～363 天，并要求它比 CA 寿命及本次请求涉及的对象 EE 寿命至少短一天。普通持久 CA 的对象 EE 仍由现有签发逻辑限制在 CA 到期之前。

## 配置何时生效

| 配置 | 生效规则 |
|---|---|
| `name` | 本地标识；不改证书 Subject |
| 对象 EE 有效期 | 进程重新加载配置后，影响后续签发；不改已有对象 |
| CRL/Manifest 时间参数 | 进程重新加载配置后，影响后续刷新；不改已有文件 |
| `ca_renew_before_days` | 影响状态提醒；不会自动续期 |
| `development_ca_validity_days` | 用于初次创建开发 TA；不延长已有证书 |
| `development_resources` / `development_asns` | 用于初次创建开发 TA；编辑文件不会获得新资源授权 |
| `repository_uri` / `certificate_uri` | 与证书及对象 URI 关联；不能仅编辑 TOML 完成迁移 |
| `rrdp_notification_uri` | 新建开发 CA 时写入证书；更改配置不更新已有证书 |

每次 CLI 操作会重新加载配置；常驻服务需要重启。修改已有 CA 的资源或仓库位置时，本项目当前建议建立新的实验 CA 并重新签发。现有换证命令要求保持同一密钥、Subject 和资源集合，不是资源变更或仓库迁移入口。修改已有配置前停止写入，校验完成后再启动；当前未提供在线配置更新命令。

## 可选 RRDP 发布地址

可选字段 `rrdp_notification_uri` 为 HTTPS RRDP notification 地址，用于新建开发 CA 证书的 `rpkiNotify`。未设置时保持原行为；修改 TOML 不会更新已有证书，导入和换证时的地址以所提供的证书为准。接入 Krill 时建议先导入 Repository Response，再使用生成的配置创建新实验 CA，参见 [Krill 发布仓库接入](krill-publication.md)。

## 只读信息查看

`ca-info` 持有状态锁读取公开材料，不打开 `ca.key`，不签发、不刷新、不自动恢复事务。锁使用现有 `state.lock`（若缺失会创建锁文件）。即使证书过期，也可以查看；损坏或无法解码的文件会报错。

JSON 中 `configured` 是当前 TOML 配置；`certificate` 是实际 CA 证书中的 Subject、Issuer、资源、URI、密钥标识和有效期；`files` 列出本地发布材料的有效时间；`warnings` 提示配置校验失败、资源或仓库 URI 不一致、未完成事务等。继承资源用 `*_inherited` 标识，其显式资源值为 null，不伪装成空资源。时间使用 Unix 秒。

该命令是信息查看，不是签名、证书链或吊销验证。`files.time_valid` 也只表示所检查的时间范围；完整验证请使用现有验证命令。导入型 CA 的上级材料时间不计入此处本地 `files`。
