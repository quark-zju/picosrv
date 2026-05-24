# picosrv

一个面向低内存 VPS 的轻量反向代理（Go 标准库实现），支持：

- 基于 `Host` 的上游转发
- HTTPS（证书文件热更新，适配 acme.sh / letsencrypt）
- WebSocket
- 敲门 Cookie 放行 + 代码化策略
- systemd socket activation（进程不直接绑定端口）

## 1. 构建

```bash
go build ./cmd/picosrv
```

使用自定义策略（build tags）：

```bash
go build -tags custom ./cmd/picosrv
```

## 2. 运行参数

必填：

- `--hmac-secret` 或 `PICOSRV_HMAC_SECRET`

可选：

- `--cert-file` 或 `PICOSRV_CERT_FILE`
- `--key-file` 或 `PICOSRV_KEY_FILE`
- `--tls-reload-interval` 或 `PICOSRV_TLS_RELOAD_INTERVAL`（默认 `30s`）

示例：

```bash
PICOSRV_HMAC_SECRET='replace-with-long-random-secret' \
./picosrv \
  --cert-file /etc/letsencrypt/live/example.com/fullchain.pem \
  --key-file /etc/letsencrypt/live/example.com/privkey.pem \
  --tls-reload-interval 30s
```

## 3. systemd 部署

示例文件在 `deploy/systemd/`：

- `picosrv.service`：服务定义
- `picosrv.socket`：同时监听 `80/443`
- `picosrv-https-only.socket`：仅监听 `443`
- `picosrv-uds.socket`：监听 UDS（`/run/picosrv/picosrv.sock`）

常见启用方式（以 80/443 为例）：

```bash
sudo cp deploy/systemd/picosrv.service /etc/systemd/system/
sudo cp deploy/systemd/picosrv.socket /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now picosrv.socket
```

查看日志：

```bash
journalctl -u picosrv.service -f
```

## 4. 策略自定义（推荐流程）

默认策略代码：

- `internal/config/default_config.go`（`//go:build !custom`）
- `internal/config/custom_config.go`（`//go:build custom`）

你可以直接修改 `internal/config/custom_config.go`，并用 `-tags custom` 编译。

另外提供模板：

- `examples/custom_policy.go.example`

可把模板内容复制到 `internal/config/custom_config.go` 后再按需修改。

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
- 若监听 `80`，服务会返回到 HTTPS 的重定向。
