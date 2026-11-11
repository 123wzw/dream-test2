# AuthKit

OAuth2 授权服务器 + 资源服务，供内部应用统一登录使用。

## 技术栈

- Python 3.12
- FastAPI + Uvicorn
- SQLite（标准库 sqlite3）

## 启动

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt

.venv/Scripts/python -m uvicorn app.main:app --reload
```

首次启动建表并写入演示数据：

| 项 | 值 |
|---|---|
| 客户端 ID | `demo-web` |
| 客户端密钥 | `demo-secret` |
| 回调地址 | `http://localhost:3000/callback` |
| 演示账号 | `alice@example.com` / `alice-pass` |

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 资源所有者登录，换取会话令牌 |
| GET | `/oauth/authorize` | 授权端点，返回 302 携带授权码 |
| POST | `/oauth/token` | 令牌端点，支持 authorization_code 与 refresh_token |
| GET | `/api/me` | 资源端点，需 Bearer 访问令牌 |
| POST | `/auth/password-reset/request` | 申请密码重置 |
| POST | `/auth/password-reset/confirm` | 使用重置令牌设置新口令 |

## 配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AUTHKIT_DB` | `./authkit.db` | SQLite 路径 |
| `AUTHKIT_JWT_SECRET` | `authkit-dev-secret` | 访问令牌签名密钥 |
| `AUTHKIT_ISSUER` | `https://authkit.local` | 令牌签发方 |

## 测试

```bash
.venv/Scripts/python -m pytest -q
```

## 已知问题

- 授权码与令牌生命周期策略待产品确认，尚未做安全评审。
- 未接入真实短信/邮件通道，重置令牌目前写日志。
