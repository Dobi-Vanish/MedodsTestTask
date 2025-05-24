package token

import (
	"auth-service/pkg/consts"
	"auth-service/pkg/errormsg"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"os"
	"time"
)

type ServiceToken struct {
	SecretKey string
}

func NewTokenService() *ServiceToken {
	return &ServiceToken{
		SecretKey: os.Getenv("SECRET_KEY"),
	}
}

// GenerateTokens when called generates access tokens.
func (ts *ServiceToken) GenerateTokens(clientIP, userAgent, guid string) (string, string, string, error) {
	pairID := uuid.New().String()
	accessToken, err := ts.GenerateAccessToken(clientIP, userAgent, guid, pairID)

	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, randomPart, err := GenerateRefreshToken(guid, pairID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, randomPart, nil
}

// GenerateAccessToken generates access tokens.
func (ts *ServiceToken) GenerateAccessToken(clientIP, userAgent, guid, pairID string) (string, error) {
	claims := jwt.MapClaims{
		"exp":       time.Now().Add(consts.AccessTokenExpireTime).Unix(),
		"iat":       time.Now().Unix(),
		"ip":        clientIP,
		"guid":      guid,
		"userAgent": userAgent,
		"pairId":    pairID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	signedToken, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", fmt.Errorf("failed to sign the token: %w", err)
	}

	return signedToken, nil
}

// GenerateRefreshToken generates refresh token.
func GenerateRefreshToken(guid, pairID string) (string, string, error) {
	tokenBytes := make([]byte, consts.RefreshTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to create random bytes: %w", err)
	}

	randomPart := base64.URLEncoding.EncodeToString(tokenBytes)

	fullToken := struct {
		GUID      string `json:"guid"`
		Token     string `json:"token"`
		ExpiresAt int64  `json:"exp"`
		PairID    string `json:"pairId"`
	}{
		GUID:      guid,
		Token:     randomPart,
		ExpiresAt: time.Now().Add(consts.RefreshTokenExpireTime).Unix(),
		PairID:    pairID,
	}

	jsonData, err := json.Marshal(fullToken)
	if err != nil {
		return "", "", errormsg.ErrUnexpectedSigningMethod
	}

	encodedToken := base64.URLEncoding.EncodeToString(jsonData)

	return encodedToken, randomPart, nil
}

// GenerateTokensWithPairID generates tokens with equal pair ID via Refresh.
func (ts *ServiceToken) GenerateTokensWithPairID(ip, ua, guid, pairID string) (string, string, string, error) {
	accessToken, err := ts.GenerateAccessToken(ip, ua, guid, pairID)

	if err != nil {
		return "", "", "", errormsg.ErrGenerateAccessToken
	}

	refreshToken, randomPart, err := GenerateRefreshToken(guid, pairID)

	if err != nil {
		return "", "", "", errormsg.ErrGenerateRefreshToken
	}

	return accessToken, refreshToken, randomPart, nil
}
