package routes

import (
	"github.com/SinisterSup/auth-service/internal/verify"
	"github.com/SinisterSup/auth-service/internal/services"

	"github.com/gin-gonic/gin"
)

func SetupAuthRoutes(router *gin.Engine) {
	authService := services.NewAuthService()

	auth := router.Group("/auth")
	{
		auth.POST("/signup", handleSignUp(authService))
		auth.POST("/signin", handleSignIn(authService))
		auth.POST("/refresh", handleRefreshToken(authService))
		auth.POST("/revoke", verify.AuthVerify(), handleRevokeToken(authService))
	}

	protected := router.Group("/protected")
	protected.Use(verify.AuthVerify())
	{
		protected.GET("/profile", handleProfile())
	}
}