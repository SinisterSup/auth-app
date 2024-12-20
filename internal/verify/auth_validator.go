package verify

import (
	"strings"

	"github.com/SinisterSup/auth-service/utils"

	"github.com/gin-gonic/gin"
)

func AuthVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "authorization header is required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(401, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			// log.Printf("Token validation has failed: %v", err)
			c.JSON(401, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("userId", claims.UserId)
		c.Set("email", claims.Email)
		c.Set("currentToken", tokenString) 

		// log.Printf("Auth verify successful. UserID: %s, Token length: %d", claims.UserId, len(tokenString))
		c.Next()
	}
}