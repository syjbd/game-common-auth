package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func GetToken(c *gin.Context, rdb *redis.Client) {
	userAuth, err := GetUserByToken(rdb, c.GetHeader("x-token"))
	if err != nil {
		Error(c, http.StatusUnauthorized, TokenError, "")
		return
	}
	token, _ := GenerateSessionToken(*userAuth)
	tokenData := &TokenData{
		User:  *userAuth,
		Token: token,
	}
	TokenSuccess(c, *tokenData)
}
