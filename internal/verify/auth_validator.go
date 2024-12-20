package verify

import (
	"log"
	"strings"

	"github.com/SinisterSup/auth-service/utils"

	"github.com/gin-gonic/gin"
)

func AuthVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("Starting auth verification")

		authHeader := c.GetHeader("Authorization")
		log.Printf("Auth header: %s", authHeader)

		if authHeader == "" {
			log.Println("No auth header found")
			c.JSON(401, gin.H{"error": "authorization header is required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("Invalid auth header format. Parts length is: %d, is bearer part?: %s", len(parts), parts[0])
			c.JSON(401, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		log.Printf("Token extracted was: %s", tokenString[:10])

		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			log.Printf("Token validation has failed: %v", err)
			c.JSON(401, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("userId", claims.UserId)
		c.Set("email", claims.Email)
		c.Set("currentToken", tokenString) 

		log.Printf("Auth verify successful. UserID: %s, Token length: %d", claims.UserId, len(tokenString))
		c.Next()
	}
}