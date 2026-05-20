package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

type UserAuth struct {
	Id         uint64
	MerchantId uint64
	PlayerId   string
	Username   string
	Avatar     string
	HookUrl    string
	HomeUrl    string
}

type JwtClaims struct {
	UserAuth
	jwt.RegisteredClaims
}

type ErrResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type TokenData struct {
	User  UserAuth
	Token string
}

type TokenResp struct {
	Code    int       `json:"code"`
	Message string    `json:"message"`
	Data    TokenData `json:"data"`
}

const (
	Success           = 200
	TokenError        = 4000
	Unauthorized      = 4001
	InvalidToken      = 4002
	MerchantSuspended = 4003
	PlayerLocked      = 4004
)

var MessageAuth = map[int]string{
	Success:           "SUCCESS",
	TokenError:        "TOKEN_ERROR",
	Unauthorized:      "UNAUTHORIZED",
	InvalidToken:      "INVALID_TOKEN",
	MerchantSuspended: "MERCHANT_SUSPENDED",
	PlayerLocked:      "PLAYER_LOCKED",
}
