package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

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

func GetUserByToken(rdb *redis.Client, tokenString string) (*MerchantUser, error) {
	ctx := context.Background()
	key := tokenString
	exists, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, errors.New("token 不存在或已过期")
	}
	var user MerchantUser
	if err := rdb.HGetAll(ctx, key).Scan(&user); err != nil {
		return nil, fmt.Errorf("反序列化用户信息失败: %w", err)
	}
	return &user, nil
}

// GenerateSessionToken 签发游戏会话 JWT token (标准有效期 2 小时)
func GenerateSessionToken(merchantUser MerchantUser) (string, error) {
	claims := JwtClaims{
		MerchantUser: merchantUser,
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
	return nil, fmt.Errorf("invalid token claims")
}

// ==========================================
// 2. Redis 安全总线（同步与监听广播）
// ==========================================

// 假设你的全局 Map 定义如下（请确保 Key 的类型是 uint64）：
// var localPlayerBlacklist = make(map[uint64]struct{})
// var localMerchantBlacklist = make(map[uint64]struct{})

// InitSecurityBus 在游戏服务启动时调用，加载历史状态并订阅秒级拉黑通道
func InitSecurityBus(rdb *redis.Client) {
	ctx := context.Background()

	// A. 预热加载：从 Redis 集合中拉取历史已被封禁的商户和玩家
	bannedPlayers, _ := rdb.SMembers(ctx, "global:blacklist:player").Result()
	bannedMerchants, _ := rdb.SMembers(ctx, "global:blacklist:merchant").Result()

	blacklistMu.Lock()
	// 修复点：显式声明为 int64，统一内存中的数据类型
	for _, pidStr := range bannedPlayers {
		var pid uint64
		if _, err := fmt.Sscanf(pidStr, "%d", &pid); err == nil {
			localPlayerBlacklist[pid] = struct{}{}
		}
	}
	for _, midStr := range bannedMerchants {
		var mid uint64
		if _, err := fmt.Sscanf(midStr, "%d", &mid); err == nil {
			localMerchantBlacklist[mid] = struct{}{}
		}
	}
	blacklistMu.Unlock()

	// B. 异步监听：基于长连接订阅实时熔断广播
	go listenChannel(rdb, "chan:player_ban", func(pid uint64) {
		blacklistMu.Lock()
		localPlayerBlacklist[pid] = struct{}{} // 现在这里完美契合 int64 的 map 了
		blacklistMu.Unlock()
	})

	go listenChannel(rdb, "chan:merchant_ban", func(mid uint64) {
		blacklistMu.Lock()
		localMerchantBlacklist[mid] = struct{}{}
		blacklistMu.Unlock()
	})
}

// 内部低级监听工具
func listenChannel(rdb *redis.Client, channel string, onMessage func(id uint64)) {
	pubSub := rdb.Subscribe(context.Background(), channel)
	defer func(pubSub *redis.PubSub) {
		_ = pubSub.Close()
	}(pubSub)

	for msg := range pubSub.Channel() {
		var id uint64
		if _, err := fmt.Sscanf(msg.Payload, "%d", &id); err == nil {
			onMessage(id)
		}
	}
}

// ==========================================
// 3. 内存快检拦截（读写分离锁，耗时微秒级）
// ==========================================

func IsMerchantBanned(mid uint64) bool {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()
	_, banned := localMerchantBlacklist[mid]
	return banned
}

func IsPlayerBanned(pid uint64) bool {
	blacklistMu.RLock()
	defer blacklistMu.RUnlock()
	_, banned := localPlayerBlacklist[pid]
	return banned
}
