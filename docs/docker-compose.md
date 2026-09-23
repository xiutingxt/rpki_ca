# Docker Compose 测试输入

复制环境变量示例并按需修改：

```bash
cp docker/.env.example docker/.env
docker compose -f docker/compose.yaml up -d --build
```

首次初始化开发用 TA 时读取以下变量：

- `CA_DATA_DIR`：宿主机持久化目录，默认 `../data/docker`，绑定到容器的 `/var/lib/rpki`。
- `REPOSITORY_URI`：仓库的公开 rsync 基础 URI，必须以 `/` 结尾。
- `CA_NAME`：本地 CA 名称。
- `DEVELOPMENT_CA_VALIDITY_DAYS`：开发 TA 证书有效天数。
- `ROA_VALID_WEEKS`：ROA EE 证书有效周数，默认 52。
- `ASPA_VALID_WEEKS`：ASPA EE 证书有效周数，默认 52。
- `TOA_VALID_WEEKS`：实验性 TOA EE 证书有效周数，默认 52。
- `TOA_REVIEW_DAYS`：TOA 运行复核周期，默认 90 天。
- `PUBLISH_NEXT_HOURS`：Manifest/CRL 基础更新周期，默认 24 小时。
- `PUBLISH_NEXT_JITTER_HOURS`：发布周期随机抖动上限，默认 4 小时。
- `PUBLISH_HOURS_BEFORE_NEXT`：距离 `nextUpdate` 多久开始自动刷新，默认 8 小时。
- `CA_RESOURCES`：空格分隔的 IPv4/IPv6 资源集合。这些资源决定该开发 TA 最多可以签发哪些 ROA 前缀。

容器内的 CA 目录固定为 `/var/lib/rpki/ca`，由 `CA_DATA_DIR` 指定的宿主机目录持久化。默认会写入仓库根目录的 `data/docker/ca`。上述初始化变量只在该目录中尚无 `ca.toml` 时生效。若要从头初始化，应先停止 Compose，再删除 `data/docker/ca`；该操作会永久删除测试 CA 的私钥、状态和已发布对象。

## 直接从 CLI 提交 ROA 意图

`--asn` 是起源 ASN，`--prefix` 可以重复。每一项可写成 `PREFIX`，也可写成 `PREFIX,MAX_LENGTH`：

```bash
docker compose -f docker/compose.yaml exec rpki-ca rpki-ca sign-roa \
  --dir /var/lib/rpki/ca \
  --asn 64496 \
  --prefix 192.0.2.0/24 \
  --prefix "2001:db8::/48,48" \
  --output /tmp/example.roa
```

CA 会检查每个前缀是否被证书资源覆盖，并检查 `maxLength` 是否有效。ASN 是 ROA 声明的路由起源 ASN；它并不是 CA 证书中的 ASN 资源授权，因此不会与 CA 的 AS Resources 扩展做覆盖比较。

`--output` 是仓库外的导出副本路径。CA 会在 `/var/lib/rpki/ca/repository` 中使用对象 EE 公钥标识符生成 RFC 6481 推荐文件名，不能由 CLI 指定或直接覆盖。

## HTTP API

Compose 默认在 `API_PORT`（默认 `3000`）启动 API。`API_TOKEN` 是必填的 Bearer Token；若前端跨域访问，可把 `CORS_ORIGIN` 设置为前端的精确来源，例如 `http://localhost:5173`。

```bash
API_TOKEN="与 docker/.env 中 API_TOKEN 相同的值"

curl --request POST http://localhost:3000/api/v1/roas \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header "Content-Type: application/json" \
  --data '{
    "asn": 64496,
    "prefixes": [
      { "prefix": "192.0.2.0/24", "max_length": 24 }
    ]
  }'
```

接口包括：

- `GET /healthz`：无需鉴权的健康检查。
- `GET /api/v1/roas`、`POST /api/v1/roas`：列出授权配置或原子应用 `{added, removed}`，ROA 不使用 `Idempotency-Key`。
- `GET/POST /api/v1/aspas`、`GET/DELETE /api/v1/aspas/{customer_asn}`：列出、批量增删、查询或撤回 ASPA；批量请求使用 `{added, removed}`，无需 `Idempotency-Key`。
- `GET/POST /api/v1/toas`、`GET/DELETE /api/v1/toas/{key}`：列出、创建、查询或撤回 TOA。
- `GET/POST /api/v1/sispis`、`GET/DELETE /api/v1/sispis/{as_id}`：列出、批量增删、查询或撤回 SiSPI；批量请求使用 `{added, removed}`，无需 `Idempotency-Key`。
- `GET /api/v1/toas/reviews`、`POST /api/v1/toas/{name}/reviews`：查询和记录 TOA 定期运行复核。
- `DELETE /api/v1/signed-objects/{name}`：按后端当前签发清单中的发布文件名撤回 ASPA、TOA 或 SiSPI，同时更新 CRL 和 Manifest；ROA 通过授权配置增量移除，不依赖 `Idempotency-Key`。
- `POST /api/v1/ca/validation-context`：更新导入 RC 的 TAL 和父级发布快照。
- `GET /repository/{name}`：下载公开的 RPKI 仓库对象。

ASPA 和 SiSPI 按稳定逻辑身份、TOA 按规范化内容摘要在后端实现幂等；重复提交相同目标状态不会重新签发。所有写接口均不要求 `Idempotency-Key`。写请求在进程内串行执行，并继续使用 CA 的文件锁保护底层状态。
