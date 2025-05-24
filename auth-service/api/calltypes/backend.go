package calltypes

import (
	"github.com/golang-jwt/jwt"
	"time"
)

// User provides structure to hold users.
type User struct {
	ID        string    `json:"id"`
	GUID      string    `json:"guid"`
	Email     string    `json:"email"`
	FirstName string    `json:"firstName,omitempty"`
	LastName  string    `json:"lastName,omitempty"`
	Password  string    `json:"-"`
	Active    int       `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// AccessTokenClaims provides structure to hold access token claims.
type AccessTokenClaims struct {
	IP        string `json:"ip"`
	GUID      string `json:"guid"`
	UserAgent string `json:"userAgent"`
	PairID    string `json:"pairId"`
	jwt.StandardClaims
}

// RegisterRequest represents user registration request.
type RegisterRequest struct {
	Email     string `example:"user@example.com"    json:"email"`
	FirstName string `example:"John"                json:"firstName"`
	LastName  string `example:"Doe"                 json:"lastName"`
	Password  string `example:"securePassword123"   json:"password"`
	Active    int    `example:"1"                   json:"active,omitempty"`
}
