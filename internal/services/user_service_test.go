package services

import (
    "context"
    // "os"
    "testing"
    // "time"

    "github.com/SinisterSup/auth-service/db"
    "github.com/SinisterSup/auth-service/internal/models"
    // "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

var testService *AuthService

func setupTestDB(t *testing.T) func() {
    ctx := context.Background()
    client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
    if err != nil {
        t.Fatal(err)
    }

    db.DB = client.Database("auth_service_test")
    testService = NewAuthService()

    return func() {
        db.DB.Drop(ctx)
        client.Disconnect(ctx)
    }
}

func TestSignUp(t *testing.T) {
    cleanup := setupTestDB(t)
    defer cleanup()

    input := models.SignUpInput{
        Email:    "test@example.com",
        Password: "password123",
    }

    user, err := testService.SignUp(input)
    if err != nil {
        t.Fatalf("Failed to sign up: %v", err)
    }
    if user.Email != input.Email {
        t.Errorf("Expected email %s, got %s", input.Email, user.Email)
    }

    _, err = testService.SignUp(input)
    if err == nil {
        t.Error("Expected error for duplicate email, got nil")
    }
}

func TestSignIn(t *testing.T) {
    cleanup := setupTestDB(t)
    defer cleanup()

    signUpInput := models.SignUpInput{
        Email:    "test@example.com",
        Password: "password123",
    }
    _, err := testService.SignUp(signUpInput)
    if err != nil {
        t.Fatalf("Failed to create test user: %v", err)
    }

    signInInput := models.SignInInput{
        Email:    "test@example.com",
        Password: "password123",
    }
    tokens, err := testService.SignIn(signInInput)
    if err != nil {
        t.Fatalf("Failed to sign in: %v", err)
    }
    if tokens.AccessToken == "" || tokens.RefreshToken == "" {
        t.Error("Expected non-empty tokens")
    }

    signInInput.Password = "wrongpassword"
    _, err = testService.SignIn(signInInput)
    if err == nil {
        t.Error("Expected error for invalid password, got nil")
    }
}
