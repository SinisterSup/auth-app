package routes

import (
	// "github.com/SinisterSup/auth-service/internal/verify"
	"log"

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
		log.Println("Starting token revocation")

		keys := ctx.Keys
		log.Printf("Context keys available are: %v", keys)

		userId, userExists := ctx.Get("userId")
		log.Printf("UserID exists: %v, Value: %v", userExists, userId)

		if !userExists {
            ctx.JSON(401, gin.H{"error": "user ID not found in context"})
            return
        }
		userIdStr, ok := userId.(string)
        if !ok {
            ctx.JSON(500, gin.H{"error": "invalid user ID format"})
            return
        }

		token, tokenExists := ctx.Get("currentToken")
		log.Printf("Token exists: %v, Value length: %v", tokenExists, 
			func() interface{} {
				if tokenStr, ok := token.(string); ok {
					return len(tokenStr)
				}
				return "not a string"
			}())
		if !tokenExists {
            ctx.JSON(401, gin.H{"error": "token not found in context"})
            return
        }
		tokenStr, ok := token.(string)
        if !ok {
            ctx.JSON(500, gin.H{"error": "invalid token format"})
            return
        }

		err := authService.RevokeToken(userIdStr, tokenStr)
		if err != nil {
			log.Printf("Token revocation failed: %v", err)
            ctx.JSON(500, gin.H{"error": "failed to revoke token: " + err.Error()})
            return
        }

		log.Println("Token revocation successful")
		ctx.JSON(200, gin.H{"message": "token revoked successfully"})
	}
}

func handleRefreshToken(authService *services.AuthService) gin.HandlerFunc {
    return func(c *gin.Context) {
        var input models.RefreshTokenInput
        if err := c.ShouldBindJSON(&input); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }

        tokens, err := authService.RefreshToken(input.RefreshToken)
        if err != nil {
            c.JSON(401, gin.H{"error": err.Error()})
            return
        }

        c.JSON(200, tokens)
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