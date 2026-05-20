package auth

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SecurityInterceptor 工业级多层拦截与自动续期中间件
// 职责：
//  1. 提取Token
//  2. 解密JWT
//  3. 拦截黑名单商户
//  4. 拦截黑名单玩家
//  5. 自动滚动续期
//  6. 状态向下传递
func SecurityInterceptor() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 获取客户端传来的 Token
		// 支持 Header Bearer / Query / X-Token
		tokenStr := getTokenFromRequest(c)
		if tokenStr == "" {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    Unauthorized,
				"message": MessageAuth[Unauthorized],
			})
			return
		}

		// 2. 本地内存数学验权 (确认签名是否被篡改或过期)
		claims, err := VerifySessionToken(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{
				"code":    InvalidToken,
				"message": MessageAuth[InvalidToken],
			})
			return
		}

		// 3. 第一层防线：校验商户状态 (大闸熔断，秒级踢出该商户下所有在线玩家)
		if IsMerchantBanned(claims.MerchantId) {
			c.AbortWithStatusJSON(403, gin.H{
				"code":    MerchantSuspended,
				"message": MessageAuth[MerchantSuspended],
			})
			return
		}

		// 4. 第二层防线：校验玩家个体状态 (精确封禁)
		if IsPlayerBanned(claims.Id) {
			c.AbortWithStatusJSON(403, gin.H{
				"code":    PlayerLocked,
				"message": MessageAuth[PlayerLocked],
			})
			return
		}

		// 5. 智能动态滚动续期 (Sliding Expiration)
		// 如果玩家正在高频交互，且 Token 寿命仅剩不足 30 分钟，自动为其续命 2 小时
		expiresAt, _ := claims.GetExpirationTime()
		if time.Until(expiresAt.Time) < 30*time.Minute {
			newToken, err := GenerateSessionToken(claims.UserAuth)
			if err == nil {
				// 塞入响应头，通知前端静默更新覆盖本地 Token 储存
				c.Header("X-Refresh-Token", newToken)
				c.Header("Access-Control-Expose-Headers", "X-Refresh-Token")
			}
		}

		// 6. 将提取出来的关键基因注入上下文，使后续的具体游戏业务无需重复解析 JWT
		c.Set(ContextKeyMerchantUser, claims.UserAuth)
		c.Next()
	}
}

// getTokenFromRequest 从请求中获取 Token
// 优先级：X-Token Header > Authorization Bearer > Query token
func getTokenFromRequest(c *gin.Context) string {
	// 1. 尝试 X-Token Header
	if token := c.GetHeader("X-Token"); token != "" {
		return token
	}

	// 2. 尝试 Authorization Bearer
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// 3. 尝试 Query String
	return c.Query("token")
}

// ContextKeyMerchantUser 上下文中的商户用户 Key
const ContextKeyMerchantUser = "merchant_user"

// GetMerchantUser 从上下文获取商户用户信息
func GetMerchantUser(c *gin.Context) (UserAuth, bool) {
	val, exists := c.Get(ContextKeyMerchantUser)
	if !exists {
		return UserAuth{}, false
	}
	user, ok := val.(UserAuth)
	return user, ok
}
