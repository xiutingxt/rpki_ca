# 导入已有 RC 或 TA

导入自签 TA：

```bash
rpki-ca import \
  --dir data \
  --certificate ta.cer \
  --private-key ta.key \
  --tal trust-anchor.tal \
  --repository-uri rsync://rpki.example.net/repo/ta/ \
  --certificate-uri 'rsync://rpki.example.net/repo/ta/<ta-key-id>.cer' \
  --serial-start 100000 \
  --publication-number-start 1
```

非自签 RC 必须提供完整认证路径。`--chain-certificate` 按 TA 到直接父 CA 排序；每个签发 CA 都必须提供相同顺序的当前 CRL 和当前 Manifest。例如 `TA -> parent -> child`：

```bash
rpki-ca import \
  --dir data \
  --certificate child.cer \
  --private-key child.key \
  --tal trust-anchor.tal \
  --repository-uri rsync://rpki.example.net/repo/child/ \
  --certificate-uri 'rsync://rpki.example.net/repo/parent/<child-key-id>.cer' \
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

上述文件路径和 URI 是示例，`<ta-key-id>` / `<child-key-id>` 须替换为对应公钥标识符的 URL-safe Base64 编码（不含填充），即项目使用的 RFC 6481 推荐文件名。传入的本地 DER 文件可以叫 `ta.cer` 或 `child.cer`；`--certificate-uri` 必须是证书的真实公开地址，其末尾文件名会用于本地仓库存储和后续验证。`--repository-uri` 必须匹配导入证书的 `caRepository` SIA，不能用配置改变证书内地址。

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

使用 Krill 时，先注册 publisher，并确认导入证书的发布目录位于分配的 `sia_base` 内；已有 `rpkiNotify` 必须匹配仓库返回的 notification URI。子 CA 证书位于父级发布点时，同步器保留本地副本用于验证，但不把证书改址发布到子级目录。后续签发、撤回、刷新和换证均需显式同步，参见 [Krill 接入指南](krill-publication.md)。

仅从 APNIC 等 RIR 公共仓库下载证书和对象，通常无法获得对应 CA 私钥，因此不能直接用下载内容冒充该 RC 签发新 ROA；实际签发必须使用由上级分配给你的资源证书和你自己控制的匹配私钥。

[返回 README](../README.md)
