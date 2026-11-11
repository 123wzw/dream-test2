# AuthKit OAuth2 授权流程安全审计报告

- 审计范围：`/oauth/authorize` → `/oauth/token` 授权码流程（含 PKCE、refresh token 轮换）
- 对照标准：RFC 6749（OAuth 2.0 授权框架）、RFC 7636（PKCE）、RFC 9700（OAuth 2.0 安全 BCP）
- 审计日期：2026-11-11
- 测试结果：`20 passed`（原有 `tests/test_functional.py` 9 个用例零修改、全部保持通过；新增 `tests/test_security.py` 11 个用例，其中 10 个攻击用例修复前全部失败、修复后全部通过，1 个 PKCE 正向用例）

## 漏洞清单

### V1. 授权端点不校验 redirect_uri（开放重定向 / 授权码外带）

| 项 | 内容 |
| --- | --- |
| 位置（修复前） | `app/main.py:65-97`（`authorize` 直接把入参 `redirect_uri` 拼进 302）、`app/oauth.py:19-27`（`issue_authorization_code` 只查 client 是否存在） |
| 位置（修复后） | `app/oauth.py:20-23`（`_validate_redirect_uri`），调用点 `app/oauth.py:50` |
| 协议依据 | RFC 6749 §3.1.2.3：重定向 URI 必须预注册，且授权服务器须按 RFC 3986 §6 的 simple string comparison 做**精确字符串匹配**；校验失败时 **MUST NOT** 自动重定向到该非法 URI。RFC 6749 §4.1.1：`redirect_uri` 是授权请求的组成部分 |
| 影响 | 攻击者构造 `redirect_uri=http://evil.example.com/...` 诱导已登录用户访问，服务器把 `code` 拼到攻击者域名的 302 中，授权码直接外带；结合 V2 即可在攻击者站点完成换 token，账号被接管 |
| 修复方式 | 新增 `_validate_redirect_uri`，从 `clients.redirect_uris` 注册列表中做精确匹配，不匹配抛 `invalid_request`（经 `main.py:90-91` 映射为 400，不发生重定向） |
| 攻击测试 | `test_attack_authorize_rejects_unregistered_redirect_uri` |

### V2. 令牌端点不比对 redirect_uri，授权端点校验可被绕过

| 项 | 内容 |
| --- | --- |
| 位置（修复前） | `app/oauth.py:35-49`（`exchange_code` 完全不使用 `redirect_uri` 参数）；`app/main.py:104` 仅检查非空 |
| 位置（修复后） | `app/oauth.py:87-90` |
| 协议依据 | RFC 6749 §4.1.3：若授权请求中包含 `redirect_uri`，令牌请求**必须**包含同一参数，且二者值 **MUST be identical** |
| 影响 | 即使 V1 被修复，窃取到授权码的攻击者可用任意 `redirect_uri` 调令牌端点换发 access token，使授权端点的绑定形同虚设 |
| 修复方式 | 换码时将入参与 `auth_codes.redirect_uri`（授权时落库的值）精确比对，不一致返回 `invalid_grant`，并再次做注册校验 |
| 攻击测试 | `test_attack_token_rejects_mismatched_redirect_uri` |

### V3. 授权码可无限重放（未强制一次性）

| 项 | 内容 |
| --- | --- |
| 位置（修复前） | `app/oauth.py:51`（旧 `mark_code_used` 只写 `used=1`，`exchange_code` 从不检查 `used` 列）、旧 `app/store.py` `mark_code_used` |
| 位置（修复后） | `app/store.py:136-156`（`claim_auth_code` 原子认领）、`app/oauth.py:94-99`（重放即吊销家族） |
| 协议依据 | RFC 6749 §4.1.2：授权码**必须短期有效且只能使用一次**；若同一 code 被使用多次，授权服务器**必须拒绝请求，并应尽可能吊销此前基于该 code 签发的全部令牌**。RFC 9700 §3.6.1（Authorization Code Replay Protection）重申该重放保护要求 |
| 影响 | 授权码在 5 分钟有效期内可被反复换发 access token + refresh token；code 一旦通过日志、Referer、浏览器历史泄露，攻击者可与合法客户端并行兑换且不会被发现 |
| 修复方式 | 新增 `claim_auth_code`：以 `UPDATE ... WHERE code=? AND used=0` 原子认领，已使用的 code 再次出现即判定重放；重放时调用 `revoke_refresh_family(code)` 吊销该授权派生出的全部 refresh token，再返回 `invalid_grant`。授权码 300 秒 TTL（RFC 6749 建议上限 10 分钟）保持不变 |
| 攻击测试 | `test_attack_authorization_code_is_single_use`、`test_attack_replayed_code_revokes_refresh_token_family` |

### V4. PKCE 完全未实现（`_check_pkce` 空实现直接放行）

| 项 | 内容 |
| --- | --- |
| 位置（修复前） | `app/oauth.py:30-32`（`_check_pkce` 函数体只有 `return None`，注释写明"等待客户端改造完成后再启用"） |
| 位置（修复后） | `app/security.py:74-92`（verifier/challenge 字符集校验与 S256 变换）、`app/oauth.py:26-41`（授权端点参数校验）、`app/oauth.py:58-71`（令牌端点比对） |
| 协议依据 | RFC 7636 §4.1：`code_verifier` 为 43–128 个非保留字符；§4.2：S256 = `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`；§4.3：`code_challenge_method` 缺省按 `plain` 处理；§4.4.1：不支持的变换方法必须返回 `invalid_request`；§4.6：令牌端点必须重算并比对，verifier 缺失/不匹配返回 `invalid_grant` |
| 影响 | 授权码注入（CSRF 式攻击）：攻击者可把自己申请到的 code 塞进受害者的客户端完成换码；下周接入的第三方公共客户端（无 client_secret 保护）在授权码泄露时没有任何第二道防线 |
| 修复方式 | 授权端点校验 challenge 格式与 method 白名单（仅 `S256`/`plain`，未知方法 400）；令牌端点在授权时带 challenge 的情况下强制要求合法 verifier，S256 做 SHA-256 比对、plain 直接比对，均使用 `hmac.compare_digest` 防时序侧信道。授权时未带 challenge 的旧客户端保持兼容（PKCE 对其仍为可选） |
| 攻击测试 | `test_attack_pkce_verifier_required_when_challenge_present`、`test_attack_pkce_wrong_verifier_rejected`、`test_attack_authorize_rejects_unknown_challenge_method`；正向对照 `test_pkce_s256_happy_path`（采用 RFC 7636 附录 B 标准测试向量） |

### V5. refresh token 不轮换、可重放、不与客户端绑定

| 项 | 内容 |
| --- | --- |
| 位置（修复前） | `app/oauth.py:64-81`（`refresh` 原样返回同一个 refresh token，且不校验该 token 是否属于当前 client） |
| 位置（修复后） | `app/store.py:57-59,71-74`（`family`/`revoked` 列与旧库迁移）、`app/store.py:171-201`（`rotate_refresh_token`/`revoke_refresh_family`）、`app/oauth.py:113-140` |
| 协议依据 | RFC 6749 §10.4：refresh token 与客户端凭据绑定，授权服务器**不得**向其他客户端发放基于该 refresh token 的访问令牌；RFC 9700 §3.3.1（Refresh Token Replay Detection）：refresh token 应一次性使用并轮换；一旦已轮换的旧令牌被再次提交（重放信号），必须视为令牌被盗并**吊销整个令牌家族** |
| 影响 | 旧实现中 refresh token 30 天内恒定不变、可无限次使用，且客户端 A 的 token 能被客户端 B 使用；一次泄露即长期沦陷，且被盗后服务端无法通过重放信号发现入侵 |
| 修复方式 | 每次刷新签发新 refresh token 并原子吊销旧令牌（轮换）；同一授权码派生的令牌以授权码为 `family` 标识归族；提交已吊销/已轮换令牌时吊销整族并返回 `invalid_grant`；新增 `client_id` 绑定校验。refresh token 30 天 TTL 保持不变 |
| 攻击测试 | `test_attack_refresh_token_rotates_on_use`、`test_attack_refresh_token_reuse_revokes_entire_family`、`test_attack_refresh_token_rejected_for_other_client` |

## 附带加固（非独立漏洞）

- `client_secret` 比较由 `!=` 改为 `hmac.compare_digest`（`app/oauth.py:77,115`），消除凭据比对的时序侧信道。
- `refresh_tokens` 表新增 `family`、`revoked` 两列，`init_db` 内含针对旧库的幂等 `ALTER TABLE` 迁移（`app/store.py:71-74`），已用旧 schema 数据库验证升级后数据无损、重复执行无副作用。

## 兼容性与约束遵守说明

- 公开接口零变更：路由路径（`/oauth/authorize`、`/oauth/token` 等）、请求字段名、响应字段名（`access_token`/`token_type`/`expires_in`/`refresh_token`）全部保持原样；错误仍以 HTTP 400 + `detail=<error>` 返回。
- `tests/test_functional.py` 未做任何修改，9 个用例持续全绿；未使用改断言、跳过、xfail 等手段。
- 运行时配置未动：`AUTHKIT_DB`、`AUTHKIT_JWT_SECRET`、`AUTHKIT_ISSUER` 等环境变量的读取方式与默认值保持不变。
- 令牌生命周期：access token 900 秒、授权码 300 秒、refresh token 30 天，均维持原值；access token 的 HS256 签名与 `exp` 校验逻辑未改。
- 新增 `tests/conftest.py` 仅用于保证每个用例运行前幂等初始化当前库，消除两个测试模块在 import 阶段设置 `AUTHKIT_DB` 的导入顺序依赖；`tests/test_security.py` 通过 autouse fixture + `monkeypatch` 使用独立临时库，与功能测试（会重置 alice 口令）完全隔离。

## 复现命令

```bash
.venv\Scripts\python -m pytest -q
```
