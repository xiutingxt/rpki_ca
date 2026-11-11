# HTTP API

默认地址为 `http://localhost:3000`；使用其他 `API_PORT` 或 `serve --bind` 时替换示例地址。`/api/v1/` 接口要求 Bearer Token；`/healthz` 和公开文件下载 `/repository/{name}` 无需鉴权。

这些接口管理和读取本地 CA 状态及发布集。远程 Krill 发布通过独立 `publisher` CLI 显式同步；API 写入、快照导出和定时刷新均不自动触发远程发布，参见 [Krill 接入指南](krill-publication.md)。

## 健康检查

```bash
curl http://localhost:3000/healthz
```

## 实验 CA 信息与公开快照

前端可读取当前 CA 证书的 Subject、有效期、实际认证资源和验证上下文模式（`development_trust_anchor` / `imported`）：

```bash
API_TOKEN="与 docker/.env 中 API_TOKEN 相同的值"
curl http://localhost:3000/api/v1/ca/info \
  --header "Authorization: Bearer ${API_TOKEN}"
```

导出当前已提交发布状态的公开材料包（tar 文件）：

```bash
curl --fail http://localhost:3000/api/v1/experiments/snapshot \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --output experiment.tar
tar -xf experiment.tar
```

包内有 `repository/`、`trust-anchor.tal`、`experiment.json` 和 `verification.json`，不含 CA 私钥。响应头 `X-Experiment-Valid` 表示导出时离线复验是否通过；即使为 `false`，包仍返回，便于检查 `verification.json`。导出只读取公开快照，不触发重签或延长有效期。

## 管理 ROA 授权

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
- `GET /api/v1/ca/info`：读取 CA 公开配置和证书实际字段，要求 Bearer Token。
- `GET /api/v1/ca/certificate`：读取当前 CA 证书有效期和续期预警状态。
- `GET /api/v1/ca/resources`：读取后端用于签发授权的实际 ASN、IPv4 和 IPv6 资源。
- `POST /api/v1/ca/certificate-renewals`：安装外部准备的同密钥、同主体和同资源的新证书；成功返回 `204 No Content`，请求字段及示例见 [CA 生命周期](ca-lifecycle.md)。
- `GET /api/v1/experiments/snapshot`：导出当前公开发布快照的 tar 包，要求 Bearer Token。
- `GET /api/v1/roas`：列出期望 ROA 授权及其派生发布对象，要求 Bearer Token。
- `POST /api/v1/roas`：原子应用 `{added, removed}` 授权增量；ROA 不使用 `Idempotency-Key`。
- `GET /api/v1/aspas`：列出当前 ASPA 定义及实际发布对象。
- `POST /api/v1/aspas`：原子应用 `{added, removed}` ASPA 批量增量；以 Customer ASN 为身份，重复提交是无操作，不使用 `Idempotency-Key`。
- `GET /api/v1/aspas/{customer_asn}`：按 Customer ASN 查询当前 ASPA；`DELETE` 同一路径撤回 ASPA。
- `GET /api/v1/toas`：列出当前 TOA 定义及实际发布对象。
- `POST /api/v1/toas`：原子应用 `{added, removed}` TOA 批量增量；每项包含完整的 `asns`、`prefixes`，按规范化内容摘要定位，重复提交是无操作。
- `GET /api/v1/toas/{key}`：按 64 个十六进制字符的 SHA-256 内容键查询当前 TOA；取响应 `logical_key` 中去掉 `toa:` 前缀的部分。`DELETE` 同一路径撤回 TOA。
- `GET /api/v1/toas/reviews`：列出已发布 TOA 的最近复核时间、下次截止时间和 ROA 覆盖状态。
- `POST /api/v1/toas/{name}/reviews`：按 TOA 发布文件名重新检查其与当前 ROA 的覆盖关系并记录一次运行复核。
- `GET /api/v1/sispis`：列出当前 SiSPI 定义及实际发布对象。
- `POST /api/v1/sispis`：原子应用 `{added, removed}` SiSPI 批量增量；以 ASN 为身份，重复提交是无操作，不使用 `Idempotency-Key`。
- `GET /api/v1/sispis/{asn}`：按 ASN 查询当前 SiSPI；`DELETE` 同一路径撤回 SiSPI。
- `DELETE /api/v1/signed-objects/{name}`：按当前 CA 签发清单中的发布文件名撤回 ASPA、TOA 或 SiSPI；ROA 必须通过授权增量移除，不能直接删除派生文件。
- `GET /api/v1/repository/objects`：列出当前真实发布仓库中的证书、CRL、Manifest、ROA、ASPA、TOA 和 SiSPI，要求 Bearer Token。
- `GET /api/v1/repository/objects/{name}`：严格解码仓库对象并返回结构化内容、SHA-256 和 Base64，要求 Bearer Token。
- `GET /api/v1/repository/objects/{name}/validation`：使用 `rpki` 库从配置的 TAL 开始验证全部父级 CA 证书、CRL 和 Manifest，再验证当前 CA 发布点的 CRL、Manifest、文件哈希、吊销状态以及 ROA/ASPA/TOA/SiSPI 的 CMS、EE 证书、Profile 和资源覆盖。导入 RC 使用最近一次提交的父级发布快照，本接口不会主动通过 RRDP/rsync 下载更新。
- `POST /api/v1/ca/validation-context`：更新导入 RC 的 TAL、父级证书、CRL 和 Manifest 本地快照；提交前会完整验证新路径并确认当前 CA 资源集合不变。
- `GET /repository/{name}`：下载本地公开的 RPKI 仓库对象，无需鉴权；该地址不是 Krill 的 RFC 8181 或 RRDP 接口。

SiSPI 请求、对象定义响应和解码详情的 `eContent.asn` 统一使用 `asn`。旧字段和旧命令行参数不再接受；旧 CA 状态与实验记录也必须使用新字段。签名对象的 DER 编码不变，实际 URL 仍为 `/api/v1/sispis/64496`。

对象详情接口的 `decoded` 按对应 ASN.1 Profile 保留字段名和层级：证书按实际 RFC 6487 / RFC 8360 Profile 展示字段及资源扩展；CRL 使用 `certificateList`、`revokedCertificates[].userCertificate/revocationDate` 和 `crlExtensions`；Manifest 使用 RFC 9286 的 `manifestNumber`、`thisUpdate`、`nextUpdate`、`fileHashAlg` 和 `fileList`；ROA、ASPA、TOA、SiSPI 的内容分别放在 `eContent` 中，按各自 RFC/Draft 展示结构；SiSPI 的 ASN 字段统一显示为 `asn`。RFC 6488 的 CMS 外层统一放在 `cms` 中。`profile` 和 `summary` 是界面元数据，不属于对象 ASN.1 内容。

管理层统一采用“对象定义/授权配置 → 调和 → 实际发布对象”的模型。ROA 保存逐条授权配置并按 Origin ASN 派生 ROA；ASPA 以 Customer ASN、SiSPI 以 ASN 作为稳定逻辑身份；TOA 使用规范化 ASN/Prefix 定义的 SHA-256 摘要作为身份，运行例外理由不参与摘要。写接口不使用 `Idempotency-Key`：重复加入 ROA 授权被拒绝，ASPA/TOA/SiSPI 的相同目标状态返回 `unchanged`；删除后可以重新创建。一批有效变更只生成一组 CRL/Manifest，并通过可恢复的本地发布事务提交。

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
rpki-ca withdraw-sispi --dir data --asn 64496
```

ROA 使用 `update-roas` 原子增删授权：

```bash
rpki-ca update-roas --dir data --delta /path/to/roa-delta.json
rpki-ca list-roas --dir data
```

[返回 README](../README.md)
