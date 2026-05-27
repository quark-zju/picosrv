# picosrv

轻量反向代理，基于 systemd socket activation，支持 HTTPS、按域名转发或提供静态文件、WebSocket、敲门访问控制。

## 快速上手

### 1. 配置

```bash
make config
```

首次运行会从 `examples/custom_local.go.example` 复制模板到 `internal/config/custom_local.go`，并打开编辑器。编辑其中的 `hostConfigs` 即可定义你的域名规则——每个域名支持两种模式：

- **反向代理** (`Upstream`)：将请求转发到指定的 HTTP 上游服务。
- **静态文件** (`RootDir`)：以只读方式提供本地目录下的文件（不能通过 `..` 或越界符号链接跳出该目录）。

示例：

```go
var hostConfigs = map[string]hostConfig{
    "app.example.com":    {Upstream: "http://127.0.0.1:8081", NeedKnock: true},
    "public.example.com": {Upstream: "http://127.0.0.1:8082", NeedKnock: false},
    "files.example.com":  {RootDir: "/srv/files.example.com", NeedKnock: false},
}
```

### 2. 构建并部署

```bash
make deploy
```

这一步会依次执行：创建 picosrv 系统用户、编译二进制、安装到 `/usr/local/bin`、生成 HMAC 密钥、安装 systemd 单元。

### 3. 准备证书

将域名证书放到 `/etc/picosrv/certs/<域名>/` 目录下，每个域名包含两个文件：

```
/etc/picosrv/certs/
└── example.com/
    ├── fullchain.pem
    └── privkey.pem
```

TLS SNI 会从完整域名开始逐级向上查找证书目录。例如 `api.example.co.uk` 会依次尝试 `api.example.co.uk`、`example.co.uk`、`co.uk`。

如果使用 acme.sh 配置域名通配符证书，可将证书直接安装到 picosrv 的证书目录：

```bash
DOMAIN=example.com
sudo install -d -m 755 /etc/picosrv/certs/$DOMAIN
acme.sh --install-cert -d '*.'"$DOMAIN" \
  --key-file /etc/picosrv/certs/$DOMAIN/privkey.pem \
  --fullchain-file /etc/picosrv/certs/$DOMAIN/fullchain.pem
```

确保 picosrv 用户能读取证书：

```bash
sudo setfacl -Rm u:picosrv:rX /etc/picosrv/certs
```

### 4. 启动

```bash
sudo systemctl enable --now picosrv.socket
```

查看日志：

```bash
journalctl -u picosrv.service -f
```

## 运行机制

- **监听方式**：进程不直接绑定端口，由 systemd 通过 socket activation 传入已监听的 socket，因此重启服务不会丢失连接。默认监听 443（HTTPS）。如需 HTTP→HTTPS 重定向，额外添加一个 `ListenStream=80` 的 socket 文件。
- **证书加载**：根据 TLS SNI 从完整域名开始逐级向上查找 `cert-dir` 下的证书目录。已使用过的证书目录会按 `tls-reload-interval` 定时重载（默认 30 秒），无需重启。
- **访问控制**：请求经过策略模块，根据 Host、Path、UA、Query、Cookie 等信息返回决策。默认策略仅作示例，生产环境通过 `internal/config/custom_local.go` 覆盖。决策类型包括：允许代理、允许文件服务、签发敲门 Cookie 并重定向、拒绝。
- **敲门 Cookie**：`HttpOnly`、`Secure`、`SameSite=Lax`，默认有效期 2 年。
- **日志**：统一输出 JSON 格式，便于 journald / Loki / ELK 等工具采集。

## 命令行参数

所有标志均可通过环境变量设置。

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `--hmac-secret` | `PICOSRV_HMAC_SECRET` | — | **必填**。HMAC 密钥 |
| `--cert-dir` | `PICOSRV_CERT_DIR` | — | 证书根目录，如 `/etc/picosrv/certs` |
| `--tls-reload-interval` | `PICOSRV_TLS_RELOAD_INTERVAL` | `30s` | 证书热加载检查间隔 |
| `--proxy-response-header-timeout` | `PICOSRV_PROXY_RESPONSE_HEADER_TIMEOUT` | `60s` | 等待上游响应头的超时 |
| `--websocket-idle-timeout` | `PICOSRV_WEBSOCKET_IDLE_TIMEOUT` | `60s` | WebSocket 上游无数据超时 |

## 测试

```bash
make test
```
