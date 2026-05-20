package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// SecurityInterceptor 工业级多层拦截与自动续期中间件
// 职责：1. 提取Token 2. 解密JWT 3. 拦截黑名单商户 4. 拦截黑名单玩家 5. 自动滚动续期 6. 状态向下传递
func SecurityInterceptor() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 获取客户端传来的 Token (支持 Header 或 QueryString)
		tokenStr := c.GetHeader("Authorization")
		if tokenStr == "" {
			tokenStr = c.Query("token")
		}
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":  401,
				"error": "UNAUTHORIZED",
				"msg":   "认证凭证丢失，请重新从商户端进入游戏",
			})
			return
		}
		fmt.Println(tokenStr)
		// 2. 本地内存数学验权 (确认签名是否被篡改或过期)
		claims, err := VerifySessionToken(tokenStr)
		fmt.Println(claims)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":  401,
				"error": "INVALID_TOKEN",
				"msg":   "凭证无效或已过期",
			})
			return
		}
		// 3. 第一层防线：校验商户状态 (大闸熔断，秒级踢出该商户下所有在线玩家)
		if IsMerchantBanned(claims.MerchantId) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":  403,
				"error": "MERCHANT_SUSPENDED",
				"msg":   "该商户合作已暂停，游戏服务不可用",
			})
			return
		}
		// 4. 第二层防线：校验玩家个体状态 (精确封禁)
		if IsPlayerBanned(claims.Id) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":  403,
				"error": "PLAYER_LOCKED",
				"msg":   "您的账号涉嫌违规，已被风控封禁",
			})
			return
		}
		// 5. 智能动态滚动续期 (Sliding Expiration)
		// 如果玩家正在高频交互，且 Token 寿命仅剩不足 30 分钟，自动为其续命 2 小时
		expiresAt, _ := claims.GetExpirationTime()
		if time.Until(expiresAt.Time) < 30*time.Minute {
			newToken, err := GenerateSessionToken(claims.MerchantUser)
			if err == nil {
				// 塞入响应头，通知前端静默更新覆盖本地 Token 储存
				c.Header("X-Refresh-Token", newToken)
				c.Header("Access-Control-Expose-Headers", "X-Refresh-Token")
			}
		}
		// 6. 将提取出来的关键基因注入上下文，使后续的具体游戏业务（如走一步、下注、Cashout）无需重复解析 JWT
		c.Set("player_id", claims.PlayerId)
		c.Set("merchant_id", claims.MerchantId)

		c.Next()
	}
}
