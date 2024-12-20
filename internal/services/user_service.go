package services

import (
	"context"
	"errors"
	"fmt"
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
	refreshToken, err := utils.GenerateRefreshToken(user.ID.Hex(), user.Email)
    if err != nil {
        return nil, err
    }

	// In order to story refresh token in database
	_, err = s.collection.UpdateOne(
        ctx,
        bson.M{"_id": user.ID},
        bson.M{"$set": bson.M{"refresh_token": refreshToken}},
    )
    if err != nil {
        return nil, errors.New("failed to store refresh token")
    }

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) RevokeToken(userId, token string) error {
	objectId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	revokedToken := models.RevokedToken{
		Token: token, 
		RevokedAt: time.Now(),
	}

	// To update revoked token in databse
	result, err := s.collection.UpdateOne(
		ctx,
		bson.M{"_id": objectId},
		bson.M{
			"$set": bson.M{"refresh_token": ""},
			"$addToSet":bson.M{
				"revoked_tokens": revokedToken,
			}, 
		},
	)

	if err != nil {
		return errors.New("failed to revoke token")
	}
    if result.ModifiedCount == 0 {
        count, err := s.collection.CountDocuments(ctx, bson.M{"_id": objectId})
        if err != nil {
            return fmt.Errorf("error checking user existence: %v", err)
        }
        if count == 0 {
            return errors.New("user not found")
        }
        return errors.New("token already revoked")
    }

	return nil
}


func (s *AuthService) RefreshToken(refreshToken string) (*models.TokenResponse, error) {
    claims, err := utils.ValidateRefreshToken(refreshToken)
    if err != nil {
        return nil, err
    }

    ctx := context.Background()

    // Check if refresh token exists in DB
    var user models.User
    err = s.collection.FindOne(ctx, bson.M{
        "_id": claims.UserId,
        "refresh_token": refreshToken,
    }).Decode(&user)

    if err != nil {
        return nil, errors.New("invalid refresh token")
    }

    newAccessToken, err := utils.GenerateToken(user.ID.Hex(), user.Email)
    if err != nil {
        return nil, err
    }
    newRefreshToken, err := utils.GenerateRefreshToken(user.ID.Hex(), user.Email)
    if err != nil {
        return nil, err
    }

    // Updating the refresh token in database
    _, err = s.collection.UpdateOne(
        ctx,
        bson.M{"_id": user.ID},
        bson.M{"$set": bson.M{"refresh_token": newRefreshToken}},
    )
    if err != nil {
        return nil, errors.New("failed to update refresh token")
    }

    return &models.TokenResponse{
        AccessToken:  newAccessToken,
        RefreshToken: newRefreshToken,
    }, nil
}