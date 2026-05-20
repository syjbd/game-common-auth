package main

import (
	"auth/auth"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func main() {
	clusterJWTSecret := "SUPER_SECRET_KEY_FOR_GAME_CLUSTER_2026_XYZ"
	auth.SetJWTSecret(clusterJWTSecret)

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	auth.InitSecurityBus(rdb)

	r := gin.Default()
	gameAPI := r.Group("/game/v1")
	gameAPI.GET("token", func(c *gin.Context) {
		user, err := auth.GetUserByToken(rdb, c.GetHeader("x-token"))
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"status": "SAFE",
				"error":  "token不存在",
				"msg":    "token 生成失败",
			})
			return
		}
		token, _ := auth.GenerateSessionToken(*user)
		c.JSON(http.StatusOK, gin.H{
			"status": "SAFE",
			"token":  token,
			"msg":    "token 生成成功",
		})
		return
	})
	gameAPI.Use(auth.SecurityInterceptor())
	{
		gameAPI.POST("/step", func(c *gin.Context) {
			// 中间件验证通过后，会将洗净的 PlayerId 和 MerchantId 自动注入上下文
			pid, _ := c.Get("player_id")
			mid, _ := c.Get("merchant_id")
			c.JSON(http.StatusOK, gin.H{
				"status":      "SAFE",
				"player_id":   pid,
				"merchant_id": mid,
				"msg":         "前进一步！本地内存安全拦截已通过",
			})
		})
	}
	r.Run(":8083")
}
