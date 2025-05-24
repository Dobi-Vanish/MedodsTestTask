package models

import (
	"auth-service/api/calltypes"
	"auth-service/pkg/consts"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"auth-service/pkg/errormsg"
	"golang.org/x/crypto/bcrypt"
)

type PostgresRepository struct {
	Conn *sql.DB
}

func NewPostgresRepository(pool *sql.DB) *PostgresRepository {
	return &PostgresRepository{
		Conn: pool,
	}
}

// Insert adds new user to the database.
func (u *PostgresRepository) Insert(user calltypes.User) (int, error) {
	if len(user.Password) < consts.PassMinLength {
		return 0, errormsg.ErrPasswordLength
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), consts.BcryptCost)
	if err != nil {
		return 0, fmt.Errorf("failed to hash password: %w", err)
	}

	var newID int

	stmt := `insert into medods (guid, email, first_name, last_name, password, active, created_at, updated_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8) returning id`

	err = u.queryRow(context.Background(), stmt,
		user.GUID,
		user.Email,
		user.FirstName,
		user.LastName,
		hashedPassword,
		user.Active,
		time.Now(),
		time.Now(),
	).Scan(&newID)
	if err != nil {
		log.Println("failed to insert new user: ", err)

		return 0, fmt.Errorf("failed to insert new user: %w", err)
	}

	return newID, nil
}

// PasswordMatches uses Go's bcrypt package to compare a user supplied password
// with the hash we have stored for a given user in the database. If the password
// and hash match, we return true; otherwise, we return false.
func (u *PostgresRepository) PasswordMatches(plainText string, user calltypes.User) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(plainText))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, fmt.Errorf("failed to compare passwords: %w", err)
		}
	}

	return true, nil
}

func (u *PostgresRepository) UpdateRefreshToken(guid, pairID, rawToken string) error {
	hashedToken, err := HashRefreshToken(rawToken)
	if err != nil {
		return err
	}

	stmt := `UPDATE medods SET refresh_token = $1, refresh_token_expires = $2, token_pair_id = $3 WHERE guid = $4`
	_, err = u.execQuery(context.Background(), stmt,
		hashedToken,
		time.Now().Add(consts.RefreshTokenExpireTime),
		pairID,
		guid,
	)

	return err
}

// DeleteRefreshToken deletes refresh token from the DB.
func (u *PostgresRepository) DeleteRefreshToken(guid string) error {
	stmt := `UPDATE medods SET refresh_token = NULL, refresh_token_expires = NULL WHERE guid = $1`

	_, err := u.execQuery(context.Background(), stmt,
		guid,
	)

	return err
}

// HashRefreshToken hashs provided refresh token.
func HashRefreshToken(token string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash refresh token: %w", err)
	}

	return string(hashedToken), nil
}

// ValidateRefreshToken validates provided refresh token.
func (u *PostgresRepository) ValidateRefreshToken(encodedToken, pairID, guid string) (bool, error) {
	jsonData, err := base64.URLEncoding.DecodeString(encodedToken)

	if err != nil {
		return false, fmt.Errorf("invalid token encoding: %w", err)
	}

	var tokenData struct {
		GUID  string `json:"guid"`
		Token string `json:"token"`
	}

	if err := json.Unmarshal(jsonData, &tokenData); err != nil {
		return false, fmt.Errorf("invalid token format: %w", err)
	}

	if tokenData.GUID != guid {
		return false, fmt.Errorf("GUID mismatch: %w", err)
	}

	var hashedToken, storedPairID string

	var expiresAt time.Time

	stmt := `SELECT refresh_token, refresh_token_expires, token_pair_id FROM medods WHERE guid = $1`
	err = u.queryRow(context.Background(), stmt, guid).Scan(&hashedToken, &expiresAt, &storedPairID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, errormsg.ErrUserNotFound
		}

		return false, fmt.Errorf("error during executing the statement: %w", err)
	}

	if pairID != storedPairID {
		return false, errormsg.ErrPairIDNotValid
	}

	if time.Now().After(expiresAt) {
		return false, errormsg.ErrTokenExpired
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(tokenData.Token))
	if err != nil {
		return false, errormsg.ErrCompareHash
	}

	return true, nil
}

func (u *PostgresRepository) execQuery(ctx context.Context, query string, args ...interface{}) (sql.Result, error) { //nolint: unparam
	ctx, cancel := context.WithTimeout(ctx, consts.DbTimeout)
	defer cancel()

	result, err := u.Conn.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query : %w", err)
	}

	return result, nil
}

func (u *PostgresRepository) queryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	ctx, cancel := context.WithTimeout(ctx, consts.DbTimeout)
	defer cancel()

	return u.Conn.QueryRowContext(ctx, query, args...)
}
