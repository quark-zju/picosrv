# picosrv

HTTPS 服务

- 配置：配置逻辑图灵完备，可按域名分别配置
- 认证：用户名密码、敲门 URL 等
- 证书：动态加载 HTTPS 证书，变化时重新加载，无需重启
- 流式：支持 WebSocket 和 SSE
- 服务：反向代理、静态文件
- 轻量：仅两千行逻辑，攻击面小；无需用 root 运行

使用场景：
- 外网 HTTPS -> 内网 HTTP 反向代理，外加简单身份认证
- 内网 LLM API 网关
- 静态文件服务

## 使用说明

### 1. 配置

picosrv 默认拒绝所有请求。必须先配置再使用。

配置文件是 `go` 语言代码，运行下面的命令编辑配置：

```bash
make config
```

默认样例展示了一些配置功能。应该不难懂，有疑问可咨询大语言模型。

配置代码可包含敏感信息，只应由可信管理员维护。不要将它加入版本控制，除非理解风险。

### 2. 构建并部署

```bash
make deploy
```

将会按需创建 picosrv 服务用户，按需生成 HMAC 密钥，编译安装主程序，以及安装 systemd 服务。

### 3. 准备证书

在 `/etc/picosrv/certs/<域名>/` 下存放证书，例如：

```
/etc/picosrv/certs/
└── example.com/
    ├── fullchain.pem
    └── privkey.pem
```

支持通配符证书。例如，域名 `api.example.com` 会依次尝试 `api.example.com`、`example.com`。

若用 acme.sh 管理通配符证书，可直接指定上述目录，如：

```bash
DOMAIN=example.com
sudo install -d -m 755 /etc/picosrv/certs/$DOMAIN
acme.sh --install-cert -d '*.'"$DOMAIN" \
  --key-file /etc/picosrv/certs/$DOMAIN/privkey.pem \
  --fullchain-file /etc/picosrv/certs/$DOMAIN/fullchain.pem
```

注：picosrv 不使用 root 运行。需要确保 picosrv 用户能读取证书：

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

### 5. 可选：部署 fail2ban

picosrv 日志在认证失败时包含 `"ban_candidate":true`。安装 fail2ban 后，可部署相关规则：

```bash
make deploy-fail2ban
sudo fail2ban-client status picosrv
```

默认 10 分钟内 5 次认证失败则封禁来源 IP 1 小时；策略标记为
`likely_abuse` 的请求单次命中即封禁 1 天。

## 运行机制

- **监听方式**：进程不直接绑定端口，由 systemd 通过 socket activation 传入已监听的 socket，因此重启服务不会丢失连接。默认监听 443（HTTPS）。如需 HTTP→HTTPS 重定向，额外添加一个 `ListenStream=80` 的 socket 文件。
- **HTTP 协议**：`--http2` 启用 HTTP/2。默认 systemd 配置启用 HTTP/2。
- **连接上限**：`--max-connections`（或 `PICOSRV_MAX_CONNECTIONS`）限制所有监听器共享的 TCP 连接总数，默认 512；HTTP、SSE 和 WebSocket 使用同一个配额。
- **证书加载**：根据 TLS SNI 从完整域名开始逐级向上查找 `cert-dir` 下的证书目录。已使用过的证书目录会按 `tls-reload-interval` 定时重载（默认 30 秒），无需重启。
- **访问控制**：请求经过策略模块，根据 Host、Path、UA、Query、Cookie 等信息返回决策。内置策略拒绝所有请求；运行 `make config` 后由 `internal/config/custom_local.go` 提供实际策略。决策类型包括：反代到私有后端（保留入口 Host）、反代到外部 API（使用上游 Host，适合内网 LLM 网关）、文件服务、签发敲门 Cookie 并重定向、拒绝。
- **敲门 Cookie**： 默认有效期 2 年。Cookie 无单独吊销列表；轮换 `PICOSRV_HMAC_SECRET` 会立即使全部现有 Cookie 失效。
- **日志**：统一输出 JSON 格式，便于 journald / Loki / ELK 等工具采集。

## 背景（为什么会有这个项目）

2026 年，LLM 能力提升，软件漏洞被频繁发现，NGINX 爆出 CVE-2026-42945 漏洞。我觉得 NGINX 功能复杂，担心攻击面大。我只用到 NGINX 一小部分功能，所以想写一个轻量的替代。同时，我也想让个人配置舒服一点，比如，不用思考 IPv6、证书、默认站、如何做嵌套 `if`。安全上，不用 root，不写磁盘，使用 systemd 隔离功能加固。

后来，我想要一个局域网 LLM 网关，集中配置 API key，也实现按需记录请求内容的调试功能。研究了 8 个开源 LLM 网关项目，它们动辄几十万、几百万行，显得笨重。在想要开新项目前，发现 `picosrv` 恰好满足需求 - 只需少量修改。包含测试只有约三千行，兼顾了 NGINX 和 LLM 网关核心功能。

## 测试

```bash
make test
```
