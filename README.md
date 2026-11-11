# silkops-auth

平台代用户调用其他服务时使用的身份凭证 SDK：调用方每个请求签一张短期凭证，被调用方验签。

凭证只说明两件事：**哪个平台在调用**（`iss`）、**代表哪个用户**（`sub`，即单点登录系统里的用户名）。凭证里不带角色和权限，这些由被调用方根据自己的数据决定。所以就算平台代码有 bug、甚至私钥泄漏，最多只能冒充某个用户，没法给任何人提权。

只依赖 Go 标准库，要求 Go 1.22 及以上。

## 安装

```bash
go get github.com/ftsxd/silkworm-ops-agent-sdk@v0.1.0
```

## 规则（SDK 已强制执行）

| 规则 | 做法 |
|---|---|
| 每个请求现签一张凭证，用过即作废 | `Signer` 不做缓存，`Transport` 在每次发送请求时签名，`Verifier` 拒绝已经用过的 `jti` |
| 有效期最长 5 分钟 | 默认 2 分钟；签名方和验证方都拒绝超过 5 分钟的凭证 |
| 只接受 EdDSA（Ed25519）和 RS256 | 算法必须与登记的公钥类型一致；`none`、`HS256` 等在使用公钥之前就会被拒绝 |
| 凭证只给指定的服务用 | 校验 `aud`，发给 A 服务的凭证拿到 B 服务无效 |
| 链路追踪 | `Transport` 自动透传 `traceparent`；中间件读取（兼容 `X-Request-Id`），没有时生成，并在响应头里带回 |

长时间运行的任务不受 5 分钟限制：任务在发起时完成鉴权，之后与这个任务相关的每个请求（轮询、续传、回答追问）都自带一张新凭证。

## 1. 生成密钥（每个调用方平台一次）

```bash
go run github.com/ftsxd/silkworm-ops-agent-sdk/cmd/silkauth-keygen -name myplatform-2026 -out ./keys
# keys/myplatform-2026.key  私钥，权限 600，留在平台上
# keys/myplatform-2026.pub  公钥，交给要调用的服务登记
```

`-name` 就是 key id（`kid`），建议带上年份，便于以后轮换。

## 2. 调用方平台（例如 myplatform）

```go
import silkauth "github.com/ftsxd/silkworm-ops-agent-sdk"

keyPEM, _ := os.ReadFile("/etc/myplatform/silkauth/myplatform-2026.key")
priv, _ := silkauth.ParsePrivateKeyPEM(keyPEM)

signer, _ := silkauth.NewSigner(silkauth.SignerConfig{
    Issuer: "myplatform",       // 在被调用方登记的平台 id
    KeyID:  "myplatform-2026",
    Key:    priv,
})

// 专门用来调用 silkworm-ops 的客户端：每个请求自动现签一张凭证
silkops := &http.Client{
    Transport: &silkauth.Transport{Signer: signer, Audience: "silkworm-ops"},
    Timeout:   0, // 流式请求不要设置整体超时
}

// 业务代码只需要说明“替谁调用”
func diagnose(w http.ResponseWriter, r *http.Request) {
    ctx := silkauth.WithSubject(r.Context(), currentUser(r).Username) // 单点登录用户名
    // 可选：用户当前正在看的应用，只用来缩小范围，不会扩大权限
    ctx = silkauth.WithHintContext(ctx, map[string]string{"project": "shop", "app": "order-svc"})
    // 可选：接入已有的链路追踪
    ctx = silkauth.WithTrace(ctx, silkauth.TraceFromRequest(r))

    req, _ := http.NewRequestWithContext(ctx, http.MethodPost, silkopsURL+"/api/v1/agent/runs", body)
    resp, err := silkops.Do(req)
    // ...
}
```

后台任务轮询结果时，用户可能已经关掉了页面。发起时把 `run_id` 和用户名一起存下来，轮询时用存下来的用户名调用 `WithSubject`。

没有设置 subject 的请求不会发出去，会直接返回 `silkauth.ErrNoSubject`。

## 3. 被调用方（例如 silkworm-ops）

```go
pubPEM, _ := os.ReadFile("platforms/myplatform-2026.pub")
pub, _ := silkauth.ParsePublicKeyPEM(pubPEM)

keys, _ := silkauth.NewStaticKeys(silkauth.Platform{
    ID:           "myplatform",
    Keys:         map[string]crypto.PublicKey{"myplatform-2026": pub},
    AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, // 可选
})

verifier, _ := silkauth.NewVerifier(silkauth.VerifierConfig{
    Audience: "silkworm-ops",
    Keys:     keys,
    Replay:   pgReplayStore, // 多实例部署必须换成共享存储，见下文
})

mux.Handle("/api/v1/agent/", verifier.Middleware(agentAPI))

// 在 handler 里取出身份
func (h *agentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    c, _ := silkauth.ClaimsFromContext(r.Context())
    // c.Issuer = "myplatform"，c.Subject = "zhangsan"，c.Context = 提示（可能为空）
    // 角色、权限由本服务自己的数据决定，凭证里的任何字段都不代表权限
    trace, _ := silkauth.TraceFrom(r.Context())
    _ = trace
}
```

验证失败一律返回 401，响应体只包含 `trace_id`，不说明失败原因（原因记在服务端日志里）。

不走 HTTP 中间件的入口（例如 A2A 的 JSON-RPC 处理器）：直接调用 `verifier.Verify(ctx, token)`，再用 `silkauth.WithClaims` 把结果放进 context。

### 多实例部署：共享的防重放存储

`MemoryReplayStore` 只能保护单个进程。多实例部署时要实现 `ReplayStore`，并保证原子性，例如：

```sql
CREATE TABLE silkauth_jti (
  issuer     TEXT NOT NULL,
  jti        TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (issuer, jti)
);
-- Use()：INSERT ... ON CONFLICT DO NOTHING，影响行数为 1 即首次使用
-- 定时：DELETE FROM silkauth_jti WHERE expires_at < now()
```

用 Redis 的话：`SET silkauth:<iss>:<jti> 1 NX EXAT <exp>`，返回 OK 即首次使用。

### 平台管理

- **轮换密钥**：先把新公钥加进 `Platform.Keys`（新旧并存），平台切换到新的 `KeyID` 签名，确认没有旧 kid 的请求后再删除旧公钥。
- **吊销平台**：`Disabled: true`，然后调用 `keys.Set(...)` 热更新，不需要重启。
- **IP 白名单**：按连接的来源地址校验，不读取 `X-Forwarded-For`。部署在反向代理后面时，白名单要填代理的地址，或者在代理层做限制。

## 4. 凭证格式

```
header  { "alg": "EdDSA", "kid": "myplatform-2026", "typ": "JWT" }
payload {
  "iss": "myplatform",
  "sub": "zhangsan",
  "aud": "silkworm-ops",
  "iat": 1762693200,
  "exp": 1762693320,
  "jti": "9f2c…（16 字节随机数）",
  "ctx": { "app": "order-svc" }   // 可选
}
```

这是标准 JWT，非 Go 的平台可以用任意 JWT 库签发：算法用 EdDSA 或 RS256（RSA 密钥至少 2048 位），字段与上面一致，每个请求生成一张。

## 测试

```bash
go test -race ./...
```

覆盖的场景：正常签发与验证、受众错误、过期、签发时间在未来、篡改 `sub`、注入 `roles`、`alg` 为 none / HS256 / 与密钥类型不符、未知的 kid、未知或已吊销的平台、用其他私钥伪造、重放（包括 50 个并发请求只有 1 个成功）、被拒的凭证不占用 jti、有效期上限、RS256 及小于 2048 位的 RSA 密钥、PEM 编解码、Transport 每个请求使用新凭证、中间件端到端、IP 白名单、traceparent 解析与透传。
