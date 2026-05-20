# 小游戏JWT公共包

## 获取公共包
```shell
go get github.com/syjbd/game-common-auth@v1.0.0
```

## 主函数
### 根据 `X-Token` 获取玩家数据和 `JWT Token`
```go
r := gin.Default()
gameApi := r.Group("/game/v1")
gameApi.GET("/token", auth.GetToken(c,rdb))
r.Run()
```

### 加载中间件
```go
gameAPI.Use(auth.SecurityInterceptor())
```