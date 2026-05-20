package auth

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// GetToken 根据 X-Token 获取玩家数据并签发游戏会话 JWT Token
// @Summary 获取游戏Token
// @Description 根据 Redis 中的 X-Token 获取玩家信息，签发新的 JWT Session Token
// @Tags Auth
// @Accept json
// @Produce json
// @Param X-Token header string true "Redis Token"
// @Success 200 {object} gin.H{code=int, data=gin.H{token=string, user=UserAuth}}
// @Failure 401 {object} gin.H{code=int, message=string}
// @Router /game/v1/token [get]
func GetToken(c *gin.Context, rdb *redis.Client) {
	// 优先从 X-Token header 获取，其次从 Authorization Bearer 获取
	token := c.GetHeader("X-Token")
	if token == "" {
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		Error(c, 401, TokenError, "missing token")
		return
	}

	userAuth, err := GetUserByToken(rdb, token)
	if err != nil {
		Error(c, 401, TokenError, err.Error())
		return
	}

	newToken, err := GenerateSessionToken(*userAuth)
	if err != nil {
		Error(c, 500, InvalidToken, "token generation failed")
		return
	}

	TokenSuccess(c, TokenData{
		User:  *userAuth,
		Token: newToken,
	})
}
