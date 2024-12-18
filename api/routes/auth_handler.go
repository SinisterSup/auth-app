package routes

import (
	// "github.com/SinisterSup/auth-service/internal/verify"
	"github.com/SinisterSup/auth-service/internal/models"
	"github.com/SinisterSup/auth-service/internal/services"

	"github.com/gin-gonic/gin"
)

func handleSignUp(authService *services.AuthService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var input models.SignUpInput
		if err := ctx.ShouldBindJSON(&input); err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}

		user, err := authService.SignUp(input)
		if err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(201, user)
	}
}

func handleSignIn(authService *services.AuthService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var input models.SignInInput
		if err := ctx.ShouldBindJSON(&input); err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}

		tokens, err := authService.SignIn(input)
		if err != nil {
			ctx.JSON(401, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(200, tokens)
	}
}

func handleRevokeToken(authService *services.AuthService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userId, _ := ctx.Get("userId")
		err := authService.RevokeToken(userId.(string))
		if err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(200, gin.H{"message": "token has been revoked"})
	}
}

func handleProfile() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId, _ := c.Get("userId")
		email, _ := c.Get("email")
		c.JSON(200, gin.H{
			"user_id": userId,
			"email":   email,
		})
	}
}