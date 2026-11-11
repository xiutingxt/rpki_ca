# CA 证书生命周期

TOML 的 `ca_renew_before_days`（默认 30 天）定义 CA 证书到期预警窗口；Docker 的首次初始化变量为 `CA_RENEW_BEFORE_DAYS`。API 服务每 10 分钟检查本地发布材料和证书有效期，并在进入窗口后输出告警。可以通过 CLI 或 HTTP API 随时读取状态：

```bash
API_TOKEN="与 docker/.env 中 API_TOKEN 相同的值"
rpki-ca certificate-status --dir data

curl http://localhost:3000/api/v1/ca/certificate \
  --header "Authorization: Bearer ${API_TOKEN}"
```

当前 CA 证书实际授权的 ASN、IPv4 和 IPv6 资源可以通过只读接口查询：

```bash
curl http://localhost:3000/api/v1/ca/resources \
  --header "Authorization: Bearer ${API_TOKEN}"
```

返回格式与 Krill CA 详情中的资源摘要一致，例如
`{"asn":"AS64496","ipv4":"192.0.2.0/24","ipv6":"2001:db8::/48"}`。
该接口展示后端已解析并用于签发授权检查的真实资源，不允许绕过上级 CA
证书直接扩大资源范围。

`renew-certificate` 安装外部准备的 DER 证书，不自动生成新 CA 证书。非自签 RC 由父 CA 为当前密钥重签；开发自签 TA 可提供同一密钥生成的新自签证书。新证书必须保持主体、公钥、解析后的资源集合和当前配置的发布目录，并且 `notAfter` 必须晚于当前证书。非自签 RC 仍需提供从 TA 到直接父 CA 的完整证书链，以及每级当前 CRL 和 Manifest：

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

续期会在同一个可恢复发布事务中替换当前 `<key-id>.cer` 并重签 CRL 和 Manifest。有效的既有 ROA/ASPA/TOA/SiSPI 沿用原字节和 EE 有效期；已过期对象随发布清理，换证不延长对象 EE 寿命。更换 CA 密钥需要单独的 key-roll 状态机，目前尚未实现。

使用 Krill 时，换证和本地材料刷新后执行 `publisher sync`；导入 RC 的父级发布快照更新仍使用 `update-validation-context`，参见 [导入 CA](import-ca.md) 和 [Krill 接入指南](krill-publication.md)。

[返回 README](../README.md)
