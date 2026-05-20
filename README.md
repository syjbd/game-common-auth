# 小游戏 JWT 公共包

基于 Go + Gin 框架的游戏认证鉴权公共库，提供高性能 JWT 验权、黑名单拦截和自动续期能力。

> **注意**：本包代码风格兼容 [darkit/gin](https://github.com/darkit/gin) API 规范，可无缝迁移至 darkit/gin 框架。

## 获取公共包

```shell
go get github.com/syjbd/game-common-auth@latest
```

## 快速开始

### 1. 初始化服务

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/redis/go-redis/v9"
    "github.com/syjbd/game-common-auth/auth"
)

func main() {
    // 初始化 Redis 客户端
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })

    // 启动安全总线（加载历史黑名单并订阅实时封禁通知）
    auth.InitSecurityBus(rdb)

    // 可选：自定义 JWT 密钥
    auth.SetJWTSecret("your-production-secret")

    // 创建 Gin 引擎
    r := gin.Default()

    // 公开接口：根据 X-Token 获取游戏会话 Token
    r.GET("/game/v1/token", func(c *gin.Context) {
        auth.GetToken(c, rdb)
    })

    // 受保护接口：加载安全拦截中间件
    gameAPI := r.Group("/game/v1")
    gameAPI.Use(auth.SecurityInterceptor())

    gameAPI.GET("/profile", func(c *gin.Context) {
        user, ok := auth.GetMerchantUser(c)
        if !ok {
            c.JSON(401, gin.H{"code": auth.Unauthorized, "message": "user not found"})
            return
        }
        auth.Success(c, gin.H{
            "player_id": user.PlayerId,
            "username":  user.Username,
        })
    })

    r.Run(":8080")
}
```

## 核心功能

### 1. Token 获取

```go
// 根据 Redis 中的 X-Token 获取玩家信息，签发 JWT Session Token
r.GET("/game/v1/token", func(c *gin.Context) {
    auth.GetToken(c, rdb)
})
```

**请求头：**
```
X-Token: your-redis-token
# 或
Authorization: Bearer your-token
```

**响应示例：**
```json
{
  "code": 200,
  "message": "SUCCESS",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "merchant_id": 100,
      "player_id": "player_001",
      "username": "张三",
      "avatar": "https://example.com/avatar.png"
    }
  }
}
```

### 2. 安全中间件

`SecurityInterceptor()` 提供六层防护：

| 层级 | 功能 | 说明 |
|------|------|------|
| 1 | Token 提取 | 支持 Header Bearer / Query / X-Token |
| 2 | JWT 验权 | 本地内存解密，无网络 IO |
| 3 | 商户熔断 | 秒级封禁商户下所有玩家 |
| 4 | 玩家封禁 | 精确封禁单个玩家 |
| 5 | 自动续期 | Token 剩余 < 30 分钟时自动续命 2 小时 |
| 6 | 上下文传递 | 后续 handler 直接获取用户信息 |

### 3. 黑名单管理

**启动时预热：**
```go
auth.InitSecurityBus(rdb) // 自动加载历史黑名单
```

**实时订阅：**
- 玩家封禁频道：`chan:player_ban`
- 商户封禁频道：`chan:merchant_ban`

**内存快检：**
```go
auth.IsMerchantBanned(merchantId) // 微秒级查询
auth.IsPlayerBanned(playerId)
```

### 4. 获取用户信息

在受保护的 handler 中获取当前用户：

```go
gameAPI.GET("/some-endpoint", func(c *gin.Context) {
    user, ok := auth.GetMerchantUser(c)
    if !ok {
        c.JSON(401, gin.H{"code": auth.Unauthorized, "message": "user not found"})
        return
    }
    // 使用 user.Id, user.MerchantId, user.PlayerId ...
    auth.Success(c, gin.H{"user_id": user.Id})
})
```

## 错误码

| 错误码 | 常量 | 说明 |
|--------|------|------|
| 200 | CodeSuccess | 成功 |
| 4000 | TokenError | Token 错误 |
| 4001 | Unauthorized | 未授权 |
| 4002 | InvalidToken | 无效 Token |
| 4003 | MerchantSuspended | 商户被封禁 |
| 4004 | PlayerLocked | 玩家被封禁 |

**错误响应示例：**
```json
{
  "code": 4001,
  "message": "UNAUTHORIZED"
}
```

## 响应头

当 Token 自动续期时，响应会包含以下头：

| Header | 说明 |
|--------|------|
| X-Refresh-Token | 新的 JWT Token，前端应替换本地存储的 Token |
| Access-Control-Expose-Headers | 值包含 X-Refresh-Token |

## API 风格兼容性

本包代码风格兼容 darkit/gin 框架，以下方法可无缝迁移：

| 本包方法 | darkit/gin 对应 |
|----------|-----------------|
| `auth.Error(c, code, bizCode, msg)` | `c.ErrorResponse(bizCode, message)` |
| `auth.TokenSuccess(c, data)` | `c.Created(gin.H{...})` |
| `auth.Success(c, data)` | `c.Success(data)` |
| `c.GetHeader("X-Token")` | `c.GetBearerToken()` |

## 迁移至 darkit/gin

当 darkit/gin 发布正式版本后，可通过以下方式迁移：

```go
// 1. 添加 go.mod replace
// replace github.com/darkit/gin => 实际路径

// 2. 替换 import
import "github.com/darkit/gin" // 替换 github.com/gin-gonic/gin

// 3. 引擎创建方式
e := gin.New()      // darkit/gin.New()
r := e.Router()     // 获取增强路由器
```

## 依赖

- [gin-gonic/gin](https://github.com/gin-gonic/gin) - Web 框架
- [golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt) - JWT 签发与验证
- [redis/go-redis/v9](https://github.com/redis/go-redis) - Redis 客户端
