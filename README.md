# picosrv

轻量可定制反向代理，支持：

- HTTPS（证书文件热更新，适配 acme.sh / letsencrypt）
- 基于 `Host` 的上游转发
- WebSocket
- systemd socket activation（进程不直接绑定端口）
- 用代码定制策略，如敲门 URL 等

## 1. 构建

```bash
go build ./cmd/picosrv
```

## 2. 运行参数

必填：

- `--hmac-secret` 或 `PICOSRV_HMAC_SECRET`

可选：

- `--cert-dir` 或 `PICOSRV_CERT_DIR`（例如 `/etc/letsencrypt/live`）
- `--tls-reload-interval` 或 `PICOSRV_TLS_RELOAD_INTERVAL`（默认 `30s`）

示例：

```bash
PICOSRV_HMAC_SECRET='replace-with-long-random-secret' \
./picosrv \
  --cert-dir /etc/letsencrypt/live \
  --tls-reload-interval 30s
```

证书查找规则：

- 根据 TLS SNI 取顶级域名（最后两段），例如 `api.example.com` 使用 `example.com`
- 从 `cert-dir/<domain>/fullchain.pem` 和 `cert-dir/<domain>/privkey.pem` 加载
- 当前只考虑这类顶级域映射，不单独处理子域证书目录
- 证书按需加载：仅在某域名首次被访问时读取该域证书
- 定时重载仅检查“已使用过”的域名证书，不扫描整个 `cert-dir`

## 3. systemd 部署

示例文件在 `deploy/systemd/`：

- `picosrv.service`：服务定义
- `picosrv.socket`：默认仅监听 `443`（强制 HTTPS）
- `picosrv-https-only.socket`：仅监听 `443`
- `picosrv-uds.socket`：监听 UDS（`/run/picosrv/picosrv.sock`）

常见启用方式（默认仅 443）：

```bash
sudo cp deploy/systemd/picosrv.service /etc/systemd/system/
sudo cp deploy/systemd/picosrv.socket /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now picosrv.socket
```

样例 `picosrv.service` 默认以 `www-data` 运行，请确认该用户对证书目录有读取权限（`/etc/letsencrypt/live` 以及其链接目标 `/etc/letsencrypt/archive`）。

查看日志：

```bash
journalctl -u picosrv.service -f
```

## 4. 策略自定义（推荐流程）

生产环境要求：默认策略仅用于示例演示，不适合生产环境。生产部署必须使用自定义策略（`internal/config/custom_local.go`）。

默认策略代码：

- `internal/config/default_config.go`

如果不想改仓库文件，推荐本地覆盖：

1. 复制 `examples/custom_local.go.example` 到 `internal/config/custom_local.go`
2. 按需修改你自己的 Host/Path/UA 规则
3. 直接正常编译（无需 build tags）

`.gitignore` 已默认忽略 `internal/config/custom_local.go`，便于保留私有策略不入库。

策略入口函数签名：

- 输入：`host/path/ua/query/cookie`
- 输出：
  - `AllowProxy(upstream)`
  - `IssueCookieAndRedirect("/")`
  - `Deny404`

## 5. 测试

```bash
go test ./cmd/picosrv ./internal/config ./internal/proxy ./internal/systemd
```

当前包含的关键测试：

- 默认拒绝
- 敲门后写 Cookie 并放行
- WebSocket 升级与双向透传
- systemd 环境前置检查

## 6. 注意事项

- 当前运行模型依赖 systemd socket activation。
- `HMAC secret` 缺失会启动失败（设计如此）。
- 默认不启用 `80` 监听；如需 HTTP 到 HTTPS 重定向，可自行增加 `ListenStream=80`。
- 敲门签名 Cookie 的服务端有效期默认是 2 年。
- `internal/config/default_config.go` 仅作参考示例，生产环境必须使用 `internal/config/custom_local.go` 自定义策略。
