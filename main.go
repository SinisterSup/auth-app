package main

import (
	"github.com/SinisterSup/auth-service/api/routes"
	"github.com/SinisterSup/auth-service/db"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading the .env file")
	}
	db.ConnectDB()

	router := gin.Default()

	routes.SetupAuthRoutes(router)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if err := router.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}
