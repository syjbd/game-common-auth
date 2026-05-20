package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MerchantUser 商户用户模型（对应 merchants_users 表）
type MerchantUser struct {
	Id         uint64    `gorm:"primaryKey;autoIncrement;column:id"`
	MerchantId uint64    `gorm:"column:merchant_id;type:int unsigned;not null"`
	PlayerId   string    `gorm:"column:merchant_player_id;type:varchar(64);not null"`
	Username   string    `gorm:"column:username;type:varchar(50);not null"`
	Avatar     string    `gorm:"column:avatar;type:varchar(255);default:null"`
	Status     int       `gorm:"column:status;type:tinyint;default:1"` // 1-启用, 0-禁用
	CreatedAt  time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt  time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (MerchantUser) TableName() string {
	return "merchants_users"
}

// Merchant 商户模型（对应 merchants 表）
type Merchant struct {
	Id           uint64    `gorm:"primaryKey;autoIncrement;column:id"`
	MerchantCode string    `gorm:"column:merchant_code;type:varchar(30);not null"`
	MerchantName string    `gorm:"column:merchant_name;type:varchar(100);not null"`
	SecretKey    string    `gorm:"column:secret_key;type:varchar(128);not null"`
	WhitelistIPs string    `gorm:"column:whitelist_ips;type:text"`
	HookUrl      string    `gorm:"column:hook_url;type:varchar(128);default null"`
	HomeUrl      string    `gorm:"column:home_url;type:varchar(128);default null"`
	Status       int8      `gorm:"column:status;type:tinyint;default:1"` // 1-启用, 0-禁用
	CreatedAt    time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (Merchant) TableName() string {
	return "merchants"
}

// UserAuth 用户认证信息（精简版，用于 JWT Claims）
type UserAuth struct {
	Id         uint64 `json:"id"`
	MerchantId uint64 `json:"merchant_id"`
	PlayerId   string `json:"player_id"`
	Username   string `json:"username"`
	Avatar     string `json:"avatar"`
	HookUrl    string `json:"hook_url,omitempty"`
	HomeUrl    string `json:"home_url,omitempty"`
}

// JwtClaims JWT Claims 结构体
type JwtClaims struct {
	UserAuth
	jwt.RegisteredClaims
}

// ErrResp 统一错误响应结构
type ErrResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// TokenData Token 响应数据
type TokenData struct {
	User  UserAuth `json:"user"`
	Token string   `json:"token"`
}

// ==========================================
// 业务错误码定义
// ==========================================

const (
	CodeSuccess       = 200   // 成功
	TokenError        = 4000  // Token 错误
	Unauthorized      = 4001  // 未授权
	InvalidToken      = 4002  // 无效 Token
	MerchantSuspended = 4003  // 商户被封禁
	PlayerLocked      = 4004  // 玩家被封禁
)

// MessageAuth 业务错误信息映射
var MessageAuth = map[int]string{
	CodeSuccess:       "SUCCESS",
	TokenError:        "TOKEN_ERROR",
	Unauthorized:      "UNAUTHORIZED",
	InvalidToken:      "INVALID_TOKEN",
	MerchantSuspended: "MERCHANT_SUSPENDED",
	PlayerLocked:      "PLAYER_LOCKED",
}
