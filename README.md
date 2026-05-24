# picosrv

轻量可定制反向代理。支持 HTTPS（证书热更新）、基于 Host 的上游转发、WebSocket、systemd socket activation、以及用 Go 代码定制访问策略（如敲门 URL）。

## 快速上手

### 1. 配置策略

```bash
cp examples/custom_local.go.example internal/config/custom_local.go
```

编辑 `internal/config/custom_local.go`，修改 `upstreams` 中的域名和上游地址。需要 SSL 证书的话，确保 `Evaluate` 里有 `/knock` 路径返回 `DecisionIssueCookieAndRedirect`（见示例）。

该文件已被 `.gitignore` 忽略，不会入仓。

### 2. 构建

```bash
go build ./cmd/picosrv
```

### 3. 部署（systemd）

```bash
sudo cp deploy/systemd/picosrv.service /etc/systemd/system/
sudo cp deploy/systemd/picosrv.socket /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now picosrv.socket
```

安装前：
- 将二进制放到 `/usr/local/bin/picosrv`
- 编辑 `/etc/systemd/system/picosrv.service`，把 `PICOSRV_HMAC_SECRET` 替换为一串随机值
- 确认运行用户（默认 `www-data`）能读取证书目录

查看日志：

```bash
journalctl -u picosrv.service -f
```

## 补充说明

- **运行参数**：`--hmac-secret`（必填）、`--cert-dir`（可选，如 `/etc/letsencrypt/live`）、`--tls-reload-interval`（默认 `30s`）。对应环境变量 `PICOSRV_HMAC_SECRET`、`PICOSRV_CERT_DIR`、`PICOSRV_TLS_RELOAD_INTERVAL`。
- **证书查找**：根据 TLS SNI 取顶级域名（最后两段），从 `<cert-dir>/<domain>/fullchain.pem` 和 `<domain>/privkey.pem` 加载。按需加载，定时重载仅检查已使用过的域名。
- **监听端口**：默认仅 443（HTTPS）。如需 HTTP→HTTPS 重定向，额外添加 `ListenStream=80` 的 socket 文件。UDS 示例见 `deploy/systemd/picosrv-uds.socket`。
- **策略接口**：输入 `host/path/ua/query/cookie`，输出 `DecisionAllowProxy` / `DecisionIssueCookieAndRedirect` / `DecisionDeny`。默认策略（`internal/config/default_config.go`）仅作示例，生产必须用 `custom_local.go`。
- **Cookie**：敲门 cookie 默认有效期 2 年，`HttpOnly`、`Secure`、`SameSite=Lax`。
- **进程模型**：依赖 systemd socket activation，进程不直接绑定端口。`HMAC secret` 缺失时启动失败。
- **测试**：`go test ./internal/config ./internal/proxy ./internal/systemd`。
