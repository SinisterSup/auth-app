package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Email        string            `bson:"email" json:"email"`
	Password     string            `bson:"password" json:"-"`
	CreatedAt    time.Time         `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time         `bson:"updated_at" json:"updated_at"`
	RefreshToken string            `bson:"refresh_token,omitempty" json:"-"`
	RevokedTokens []RevokedToken    `bson:"revoked_tokens,omitempty" json:"-"`
}

type RevokedToken struct {
	Token     string    `bson:"token"`
	RevokedAt time.Time `bson:"revoked_at"`
}

type SignUpInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}