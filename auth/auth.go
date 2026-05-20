package auth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// 全局加密密钥（建议实际生产中从小游戏的配置中心/环境变量中传入，此处赋默认值）
var jwtSecret = []byte("your_game_cluster_global_secret_xyz123")

// 核心内存黑名单（Key使用基础数值类型，完美绕过 Go GC 标记扫描，性能极高）
var (
	blacklistMu            sync.RWMutex
	localPlayerBlacklist   = map[uint64]struct{}{} // 玩家黑名单
	localMerchantBlacklist = map[uint64]struct{}{} // 商户黑名单
)

// SetJWTSecret 允许小游戏后端启动时自定义覆盖全局密钥
func SetJWTSecret(secret string) {
	if secret != "" {
		jwtSecret = []byte(secret)
	}
}

// GetUserByToken 根据 Token 从 Redis 获取玩家和商户数据
func GetUserByToken(rdb *redis.Client, token string) (*UserAuth, error) {
	ctx := context.Background()
	key := token

	exists, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, errors.New("token 不存在或已过期")
	}

	userData, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("获取用户信息失败: %w", err)
	}

	merchantIdStr, ok := userData["merchant_id"]
	if !ok {
		return nil, errors.New("用户信息缺少 merchant_id")
	}

	merchantId, err := strconv.ParseUint(merchantIdStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("merchant_id 解析失败: %w", err)
	}

	merchantKey := "merchant:" + strconv.FormatUint(merchantId, 10)
	merchantData, err := rdb.HGetAll(ctx, merchantKey).Result()
	if err != nil {
		return nil, fmt.Errorf("获取商户信息失败: %w", err)
	}

	var user MerchantUser
	if err := scanMapToStruct(userData, &user); err != nil {
		return nil, fmt.Errorf("反序列化用户信息失败: %w", err)
	}

	var merchant Merchant
	if err := scanMapToStruct(merchantData, &merchant); err != nil {
		return nil, fmt.Errorf("反序列化商户信息失败: %w", err)
	}

	return &UserAuth{
		Id:         user.Id,
		MerchantId: user.MerchantId,
		PlayerId:   user.PlayerId,
		Username:   user.Username,
		Avatar:     user.Avatar,
		HookUrl:    merchant.HookUrl,
		HomeUrl:    merchant.HomeUrl,
	}, nil
}

// scanMapToStruct 将 Redis HGETALL 的 map 结果扫描到结构体
func scanMapToStruct(m map[string]string, v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return errors.New("v must be a pointer")
	}
	rv = rv.Elem()
	rt := rv.Type()

	for i := 0; i < rt.NumField(); i++ {
		field := rv.Field(i)
		fieldType := rt.Field(i)

		// 优先获取 gorm tag 中的 column 值
		tag := fieldType.Tag.Get("gorm")
		colName := parseGormColumn(tag)

		if colName != "" && field.CanSet() {
			if val, ok := m[colName]; ok {
				setFieldValue(field, val)
			}
		}
	}
	return nil
}

// parseGormColumn 从 gorm tag 中提取 column 值
func parseGormColumn(tag string) string {
	for _, part := range strings.Split(tag, ";") {
		kv := strings.Split(strings.TrimSpace(part), ":")
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == "column" {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

// setFieldValue 根据字段类型设置值
func setFieldValue(field reflect.Value, val string) {
	switch field.Kind() {
	case reflect.Uint64:
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			field.SetUint(v)
		}
	case reflect.Uint:
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			field.SetUint(v)
		}
	case reflect.Int:
		if v, err := strconv.Atoi(val); err == nil {
			field.SetInt(int64(v))
		}
	case reflect.Int8:
		if v, err := strconv.ParseInt(val, 10, 8); err == nil {
			field.SetInt(v)
		}
	case reflect.String:
		field.SetString(val)
	case reflect.Bool:
		if v, err := strconv.ParseBool(val); err == nil {
			field.SetBool(v)
		}
	}
}

// ==========================================
// JWT Token 管理
// ==========================================

// GenerateSessionToken 签发游戏会话 JWT token (标准有效期 2 小时)
func GenerateSessionToken(userAuth UserAuth) (string, error) {
	claims := JwtClaims{
		UserAuth: userAuth,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// VerifySessionToken 本地内存解密验证 JWT Token (解密计算，无任何网络/IO开销)
func VerifySessionToken(tokenString string) (*JwtClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token claims")
}

// ==========================================
// Redis 安全总线（同步与监听广播）
// ==========================================

// InitSecurityBus 在游戏服务启动时调用，加载历史状态并订阅秒级拉黑通道
func InitSecurityBus(rdb *redis.Client) {
	ctx := context.Background()

	// A. 预热加载：从 Redis 集合中拉取历史已被封禁的商户和玩家
	bannedPlayers, _ := rdb.SMembers(ctx, "global:blacklist:player").Result()
	bannedMerchants, _ := rdb.SMembers(ctx, "global:blacklist:merchant").Result()

	blacklistMu.Lock()
	for _, pidStr := range bannedPlayers {
		if pid, err := strconv.ParseUint(pidStr, 10, 64); err == nil {
			localPlayerBlacklist[pid] = struct{}{}
		}
	}
	for _, midStr := range bannedMerchants {
		if mid, err := strconv.ParseUint(midStr, 10, 64); err == nil {
			localMerchantBlacklist[mid] = struct{}{}
		}
	}
	blacklistMu.Unlock()

	// B. 异步监听：基于长连接订阅实时熔断广播
	go listenChannel(rdb, "chan:player_ban", func(pid uint64) {
		blacklistMu.Lock()
		localPlayerBlacklist[pid] = struct{}{}
		blacklistMu.Unlock()
	})

	go listenChannel(rdb, "chan:merchant_ban", func(mid uint64) {
		blacklistMu.Lock()
		localMerchantBlacklist[mid] = struct{}{}
		blacklistMu.Unlock()
	})
}

// listenChannel 内部低级监听工具
func listenChannel(rdb *redis.Client, channel string, onMessage func(id uint64)) {
	pubSub := rdb.Subscribe(context.Background(), channel)
	defer pubSub.Close()

	for msg := range pubSub.Channel() {
		if id, err := strconv.ParseUint(msg.Payload, 10, 64); err == nil {
			onMessage(id)
		}
	}
}

// ==========================================
// 内存快检拦截（读写分离锁，耗时微秒级）
// ==========================================

// IsMerchantBanned 检查商户是否被封禁
func IsMerchantBanned(mid uint64) bool {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()
	_, banned := localMerchantBlacklist[mid]
	return banned
}

// IsPlayerBanned 检查玩家是否被封禁
func IsPlayerBanned(pid uint64) bool {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()
	_, banned := localPlayerBlacklist[pid]
	return banned
}

// ==========================================
// 统一错误响应（兼容 darkit-gin API 风格）
// ==========================================

// Error 返回统一错误格式
// 兼容 darkit-gin 的 ErrorResponse 语义
func Error(c *gin.Context, httpCode, bizCode int, message string) {
	if message == "" {
		if msg, ok := MessageAuth[bizCode]; ok {
			message = msg
		} else {
			message = "UNKNOWN_ERROR"
		}
	}
	c.JSON(httpCode, ErrResp{
		Code:    bizCode,
		Message: message,
	})
}

// TokenSuccess 返回 Token 获取成功
// 兼容 darkit-gin 的 Created 语义
func TokenSuccess(c *gin.Context, data TokenData) {
	c.JSON(200, gin.H{
		"code":    CodeSuccess,
		"message": MessageAuth[CodeSuccess],
		"data": gin.H{
			"token": data.Token,
			"user":  data.User,
		},
	})
}

// Success 返回统一成功格式
func Success(c *gin.Context, data interface{}) {
	c.JSON(200, gin.H{
		"code":    CodeSuccess,
		"message": MessageAuth[CodeSuccess],
		"data":    data,
	})
}
