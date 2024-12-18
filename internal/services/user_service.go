package services

import (
	"context"
	"errors"
	// "fmt"
	"time"

	"github.com/SinisterSup/auth-service/db"
	"github.com/SinisterSup/auth-service/internal/models"
	"github.com/SinisterSup/auth-service/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type AuthService struct {
	collection *mongo.Collection
}

func NewAuthService() *AuthService {
	return &AuthService{
		collection: db.DB.Collection("users"),
	}
}

func (s *AuthService) SignUp(input models.SignUpInput) (*models.User, error) {
	ctx := context.Background()

	var existingUser models.User
	err := s.collection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&existingUser)
	if err == nil {
		return nil, errors.New("already registered email")
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:     input.Email,
		Password:  hashedPassword,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result, err := s.collection.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	// fmt.Println(user)
	return user, nil
}

func (s *AuthService) SignIn(input models.SignInInput) (*models.TokenResponse, error) {
	ctx := context.Background()

	var user models.User
	err := s.collection.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		return nil, errors.New("invalid username or password credentials")
	}

	if !utils.CheckPassword(input.Password, user.Password) {
		return nil, errors.New("invalid password credentials")
	}

	accessToken, err := utils.GenerateToken(user.ID.Hex(), user.Email)
	if err != nil {
		return nil, err
	}
	// fmt.Println(accessToken)

	return &models.TokenResponse{
		AccessToken:  accessToken,
	}, nil
}

func (s *AuthService) RevokeToken(userId string) error {
	objectId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return err
	}

	_, err = s.collection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectId},
		bson.M{"$set": bson.M{"refresh_token": ""}},
	)
	return err
}