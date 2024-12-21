package routes

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"

    "github.com/SinisterSup/auth-service/db"
    "github.com/SinisterSup/auth-service/internal/models"
    "github.com/gin-gonic/gin"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

func setupTestEnv(t *testing.T) (*gin.Engine, func()) {
    os.Setenv("JWT_SECRET", "CFRVAbtWMSrDdQbh9WOFUGGPsfsGasHKsaikAspYL6HRLE")
    os.Setenv("JWT_EXPIRY", "24h")
    
    ctx := context.Background()
    client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
    if err != nil {
        t.Fatal(err)
    }
    
    db.DB = client.Database("auth_service_test")
    
    gin.SetMode(gin.TestMode)
    router := gin.Default()
    SetupAuthRoutes(router)

    cleanup := func() {
        if err := db.DB.Drop(ctx); err != nil {
            t.Logf("Failed to drop test database: %v", err)
        }
        if err := client.Disconnect(ctx); err != nil {
            t.Logf("Failed to disconnect test client: %v", err)
        }
    }
    
    return router, cleanup
}

func TestSignUpEndpoint(t *testing.T) {
    router, cleanup := setupTestEnv(t)
    defer cleanup()

    input := models.SignUpInput{
        Email:    "test@example.com",
        Password: "password123",
    }
    body, _ := json.Marshal(input)

    w := httptest.NewRecorder()
    req, _ := http.NewRequest("POST", "/auth/signup", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    router.ServeHTTP(w, req)

    if w.Code != http.StatusCreated {
        t.Errorf("Expected status 201, got %d", w.Code)
    }

    w = httptest.NewRecorder()
    req, _ = http.NewRequest("POST", "/auth/signup", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    router.ServeHTTP(w, req)

    if w.Code != http.StatusBadRequest {
        t.Errorf("Expected status 400 for duplicate email, got %d", w.Code)
    }
}

func TestSignInEndpoint(t *testing.T) {
    router, cleanup := setupTestEnv(t)
    defer cleanup()

    signUpInput := models.SignUpInput{
        Email:    "test@example.com",
        Password: "password123",
    }
    body, _ := json.Marshal(signUpInput)
    w := httptest.NewRecorder()
    req, _ := http.NewRequest("POST", "/auth/signup", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    router.ServeHTTP(w, req)

    signInInput := models.SignInInput{
        Email:    "test@example.com",
        Password: "password123",
    }
    body, _ = json.Marshal(signInInput)
    w = httptest.NewRecorder()
    req, _ = http.NewRequest("POST", "/auth/signin", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    router.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }

    var response models.TokenResponse
    json.Unmarshal(w.Body.Bytes(), &response)
    if response.AccessToken == "" || response.RefreshToken == "" {
        t.Error("Expected non-empty tokens in response")
    }
}
