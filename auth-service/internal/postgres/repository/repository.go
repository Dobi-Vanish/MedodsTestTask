package repository

import (
	"auth-service/api/calltypes"
)

type Repository interface {
	Insert(user calltypes.User) (int, error)
	PasswordMatches(plainText string, user calltypes.User) (bool, error)
	DeleteRefreshToken(guid string) error
	ValidateRefreshToken(rawToken, pairID, guid string) (bool, error)
	UpdateRefreshToken(guid, pairID, rawToken string) error
}
