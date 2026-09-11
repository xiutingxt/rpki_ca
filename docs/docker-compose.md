# Docker Compose 测试输入

复制环境变量示例并按需修改：

```bash
cp docker/.env.example docker/.env
docker compose -f docker/compose.yaml up -d --build
```

首次初始化开发用 TA 时读取以下变量：

- `REPOSITORY_URI`：仓库的公开 rsync 基础 URI，必须以 `/` 结尾。
- `CA_NAME`：本地 CA 名称。
- `DEVELOPMENT_CA_VALIDITY_DAYS`：开发 TA 证书有效天数。
- `ROA_VALID_WEEKS`：ROA EE 证书有效周数，默认 52。
- `ASPA_VALID_WEEKS`：ASPA EE 证书有效周数，默认 52。
- `PUBLISH_NEXT_HOURS`：Manifest/CRL 基础更新周期，默认 24 小时。
- `PUBLISH_NEXT_JITTER_HOURS`：发布周期随机抖动上限，默认 4 小时。
- `PUBLISH_HOURS_BEFORE_NEXT`：距离 `nextUpdate` 多久开始自动刷新，默认 8 小时。
- `CA_RESOURCES`：空格分隔的 IPv4/IPv6 资源集合。这些资源决定该开发 TA 最多可以签发哪些 ROA 前缀。

容器内的数据目录固定为 `/data`，由 `rpki-ca-data` 命名卷持久化。上述环境变量只在该卷中尚无 `ca.toml` 时生效。若要使用新配置从头初始化，可执行 `docker compose -f docker/compose.yaml down --volumes`；该命令会永久删除测试 CA 的私钥、状态和已发布对象。

## 直接从 CLI 提交 ROA 意图

`--asn` 是起源 ASN，`--prefix` 可以重复。每一项可写成 `PREFIX`，也可写成 `PREFIX,MAX_LENGTH`：

```bash
docker compose -f docker/compose.yaml exec rpki-ca rpki-ca sign-roa \
  --dir /data \
  --asn 64496 \
  --prefix 192.0.2.0/24 \
  --prefix "2001:db8::/48,48" \
  --output /tmp/example.roa
```

也可以继续使用 JSON 文件：

```bash
docker compose -f docker/compose.yaml exec rpki-ca rpki-ca sign-roa \
  --dir /data \
  --request /app/examples/roa.json \
  --output /tmp/example.roa
```

`--request` 与 `--asn`/`--prefix` 两种方式互斥。无论采用哪一种，CA 都会检查每个前缀是否被证书资源覆盖，并检查 `maxLength` 是否有效。ASN 是 ROA 声明的路由起源 ASN；它并不是 CA 证书中的 ASN 资源授权，因此不会与 CA 的 AS Resources 扩展做覆盖比较。

`--output` 是仓库外的导出副本路径。CA 会在 `/data/repository` 中使用对象 EE 公钥标识符生成 RFC 6481 推荐文件名，不能由 CLI 指定或直接覆盖。

## HTTP API

Compose 默认在 `API_PORT`（默认 `3000`）启动 API。`API_TOKEN` 是必填的 Bearer Token；若前端跨域访问，可把 `CORS_ORIGIN` 设置为前端的精确来源，例如 `http://localhost:5173`。

```bash
API_TOKEN="与 docker/.env 中 API_TOKEN 相同的值"

curl --request POST http://localhost:3000/api/v1/roas \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header "Idempotency-Key: test-roa-001" \
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
- `POST /api/v1/roas`：签发 ROA，要求 Bearer Token 和 `Idempotency-Key`。
- `GET /api/v1/roas/{id}`：查询幂等请求结果，要求 Bearer Token。
- `GET /repository/{name}`：下载公开的 RPKI 仓库对象。

同一对象类型中，相同 `Idempotency-Key` 和相同请求会返回原结果；相同 key 搭配不同请求会被拒绝。ROA 和 ASPA 使用独立幂等命名空间。写请求在进程内串行执行，并继续使用 CA 的文件锁保护底层状态。
