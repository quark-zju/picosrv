# picosrv

轻量可定制反向代理。支持 HTTPS（证书热更新）、基于 Host 的上游转发、按 Host 映射本地只读文件目录、WebSocket、systemd socket activation、以及用 Go 代码定制访问策略（如敲门 URL）。

## 快速上手

### 1. 配置策略

```bash
cp examples/custom_local.go.example internal/config/custom_local.go
```

编辑 `internal/config/custom_local.go`，修改 `hostConfigs` 中的域名配置。每个 Host 可选择：
- `Upstream`：转发到本地或远端 HTTP 服务
- `RootDir`：把某个本地目录作为只读静态文件根目录

`RootDir` 模式下，服务端会将访问严格限制在该目录树内，不能通过 `..` 或越界符号链接跳出到父目录。

### 2. 构建

```bash
go build ./cmd/picosrv
```

### 3. 部署（systemd）

#### 3.1 安装二进制

```bash
sudo cp picosrv /usr/local/bin/picosrv
sudo chmod 755 /usr/local/bin/picosrv
```

#### 3.2 创建服务用户

```bash
sudo adduser \
  --system \
  --group \
  --home /nonexistent \
  --no-create-home \
  picosrv
```

#### 3.3 配置证书目录权限

安装 `setfacl` / `getfacl` 所在软件包（Debian/Ubuntu 为 `acl`）：

```bash
sudo apt-get install acl
```

准备证书目录：

```bash
sudo install -d -m 755 /etc/picosrv/certs
```

如果使用 `acme.sh`，可以把证书安装到 `picosrv` 自己的目录：

```bash
DOMAIN=example.com
sudo install -d -m 755 /etc/picosrv/certs/$DOMAIN
acme.sh --install-cert -d '*.'"$DOMAIN" \
  --key-file /etc/picosrv/certs/$DOMAIN/privkey.pem \
  --fullchain-file /etc/picosrv/certs/$DOMAIN/fullchain.pem \
  --reloadcmd "systemctl restart picosrv"
```

给服务账号开放证书目录的穿越权限，以及目标域名证书的只读权限：

```bash
DOMAIN=example.com
sudo setfacl -m u:picosrv:rx /etc/picosrv/certs
sudo setfacl -m u:picosrv:rx /etc/picosrv/certs/$DOMAIN
sudo setfacl -m u:picosrv:r /etc/picosrv/certs/$DOMAIN/fullchain.pem
sudo setfacl -m u:picosrv:r /etc/picosrv/certs/$DOMAIN/privkey.pem
```

确认 `picosrv` 用户确实能读取证书：

```bash
DOMAIN=example.com
sudo -u picosrv test -r /etc/picosrv/certs/$DOMAIN/fullchain.pem
sudo -u picosrv test -r /etc/picosrv/certs/$DOMAIN/privkey.pem
```

两条命令都返回退出码 `0` 即表示可读；也可以用 `getfacl` 查看当前 ACL：

```bash
getfacl /etc/picosrv/certs
getfacl /etc/picosrv/certs/$DOMAIN
```

#### 3.4 安装并启动服务

```bash
sudo cp deploy/systemd/picosrv.service /etc/systemd/system/
sudo cp deploy/systemd/picosrv.socket /etc/systemd/system/
sudo systemctl daemon-reload
```

推荐使用 `systemctl edit` 覆盖 secret（无需修改主 service 文件）：

```bash
sudo systemctl edit picosrv.service
```

写入：

```ini
[Service]
Environment=
Environment=PICOSRV_HMAC_SECRET=replace-with-long-random-secret
```

然后启动：

```bash
sudo systemctl enable --now picosrv.socket
```

查看日志：

```bash
journalctl -u picosrv.service -f
```

## 补充说明

- **运行参数**：`--hmac-secret`（必填）、`--cert-dir`（可选，如 `/etc/picosrv/certs`）、`--tls-reload-interval`（默认 `30s`）、`--proxy-response-header-timeout`（默认 `60s`）。对应环境变量 `PICOSRV_HMAC_SECRET`、`PICOSRV_CERT_DIR`、`PICOSRV_TLS_RELOAD_INTERVAL`、`PICOSRV_PROXY_RESPONSE_HEADER_TIMEOUT`。
- **反代超时**：`--proxy-response-header-timeout` 控制等待上游返回响应头的时间，默认 `60s`。对应环境变量 `PICOSRV_PROXY_RESPONSE_HEADER_TIMEOUT`。
- **证书查找**：根据 TLS SNI 取顶级域名（最后两段），从 `<cert-dir>/<domain>/fullchain.pem` 和 `<domain>/privkey.pem` 加载。按需加载，定时重载仅检查已使用过的域名。
- **监听端口**：默认仅 443（HTTPS）。如需 HTTP→HTTPS 重定向，额外添加 `ListenStream=80` 的 socket 文件。UDS 示例见 `deploy/systemd/picosrv-uds.socket`。
- **策略接口**：输入 `host/path/ua/query/cookie`，输出 `DecisionAllowProxy` / `DecisionAllowFiles` / `DecisionIssueCookieAndRedirect` / `DecisionDeny`。默认策略（`internal/config/default_config.go`）仅作示例，生产必须用 `custom_local.go`。
- **本地文件服务**：`DecisionAllowFiles` 使用配置中的 `RootDir` 作为静态文件根目录，只读访问，不允许跳出该目录树。
- **Cookie**：敲门 cookie 默认有效期 2 年，`HttpOnly`、`Secure`、`SameSite=Lax`。
- **进程模型**：依赖 systemd socket activation，进程不直接绑定端口。`HMAC secret` 缺失时启动失败。
- **测试**：`go test ./internal/config ./internal/proxy ./internal/systemd`。
