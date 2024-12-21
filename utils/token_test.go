package utils

import (
    "context"
    "os"
    "testing"
    "time"

    "github.com/SinisterSup/auth-service/db"
    "github.com/golang-jwt/jwt/v5"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

func setupTestDB(t *testing.T) func() {
    ctx := context.Background()
    client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
    if err != nil {
        t.Fatal(err)
    }

    db.DB = client.Database("auth_service_test")

    return func() {
        if err := db.DB.Drop(ctx); err != nil {
            t.Logf("Failed to drop test database: %v", err)
        }
        if err := client.Disconnect(ctx); err != nil {
            t.Logf("Failed to disconnect test client: %v", err)
        }
    }
}

func TestGenerateAndValidateToken(t *testing.T) {
    cleanup := setupTestDB(t)
    defer cleanup()
    
    os.Setenv("JWT_SECRET", "test-secret")
    
    userId := "507f1f77bcf86cd799439011"
    email := "test@example.com"
    
    token, err := GenerateToken(userId, email)
    if err != nil {
        t.Fatalf("Failed to generate token: %v", err)
    }
    
    claims, err := ValidateTokenWithOptions(token, true)
    if err != nil {
        t.Fatalf("Failed to validate token: %v", err)
    }
    
    if claims.UserId != userId {
        t.Errorf("Expected user ID %s, got %s", userId, claims.UserId)
    }
    if claims.Email != email {
        t.Errorf("Expected email %s, got %s", email, claims.Email)
    }
}

func TestTokenExpiry(t *testing.T) {
    cleanup := setupTestDB(t)
    defer cleanup()
    
    os.Setenv("JWT_SECRET", "test-secret")
    
    claims := JWTClaim{
        UserId: "testuser",
        Email:  "test@example.com",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
    
    _, err := ValidateTokenWithOptions(tokenString, true)
    if err == nil {
        t.Error("Expected error for expired token, got nil")
    }
}

// func TestTokenRevocation(t *testing.T) {
//     cleanup := setupTestDB(t)
//     defer cleanup()
    
//     os.Setenv("JWT_SECRET", "test-secret")
    
//     userId := "507f1f77bcf86cd799439011"
//     email := "test@example.com"

//     token, _ := GenerateToken(userId, email)

//     _, err := ValidateToken(token)
//     if err != nil {
//         t.Errorf("Expected token to be valid, got error: %v", err)
//     }
// }