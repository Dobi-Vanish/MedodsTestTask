// Package service implements reward service API handlers.
package service

import (
	"auth-service/api/calltypes"
	"auth-service/api/server/httputils"
	"auth-service/internal/postgres/repository"
	"auth-service/internal/token"
	"auth-service/pkg/consts"
	"auth-service/pkg/errormsg"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func NewRewardService(repo repository.Repository) *RewardService {
	return &RewardService{
		Repo:   repo,
		Client: &http.Client{},
	}
}

func (s *RewardService) ParseAccessToken(tokenString string) (*calltypes.AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&calltypes.AccessTokenClaims{},
		func(_ *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("SECRET_KEY")), nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*calltypes.AccessTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errormsg.ErrInvalidToken
}

func GetGUIDFromURL(r *http.Request, paramName string) (string, error) {
	guidStr := chi.URLParam(r, paramName)
	guidStr = strings.TrimSpace(guidStr)

	if guidStr == "" {
		return "", errormsg.ErrEmptyGUID
	}

	guid, err := uuid.Parse(guidStr)
	if err != nil {
		return "", errormsg.ErrInvalidGUID
	}

	return guid.String(), nil
}

func GetClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}

	return ip
}

// GetGUID
// @Summary Get current user GUID
// @Description Returns GUID of authenticated user from access token
// @Tags Authentication
// @Produce json
// @Success 200 {object} calltypes.JSONResponse
// @Failure 401 {object} calltypes.ErrorResponse
// @Security ApiKeyAuth
// @Router /getguid [get].
func (s *RewardService) GetGUID(w http.ResponseWriter, r *http.Request) {
	accessTokenReceived, err := (r.Cookie("accessToken"))
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	guid, err := ExtractGUIDFromToken(accessTokenReceived.Value)

	if err != nil || guid == "" {
		httputils.ErrorJSON(w, errormsg.ErrEmptyGUID, http.StatusUnauthorized)

		return
	}

	claims, err := s.ParseAccessToken(accessTokenReceived.Value)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	fmt.Printf(
		"User GUID: %s, IP: %s, UserAgent: %s\n",
		claims.GUID,
		claims.IP,
		claims.UserAgent,
	)

	payload := calltypes.JSONResponse{
		Error:   false,
		Message: "Current user GUID",
		Data:    map[string]string{"guid": guid},
	}

	err = httputils.WriteJSON(w, http.StatusOK, payload, nil)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusInternalServerError)

		return
	}
}

// Registrate
// @Summary Register new user
// @Description Creates new user account
// @Tags Authentication
// @Accept json
// @Produce json
// @Param input body calltypes.RegisterRequest true "User registration data"
// @Success 200 {object} calltypes.JSONResponse
// @Failure 400 {object} calltypes.ErrorResponse
// @Router /registrate [post].
func (s *RewardService) Registrate(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Password  string `json:"password"`
		Active    int    `json:"active,omitempty"`
	}

	err := httputils.ReadJSON(w, r, &requestPayload)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusBadRequest)

		return
	}

	if len(requestPayload.Password) < consts.AtLeastPassLength {
		httputils.ErrorJSON(w, errormsg.ErrPasswordLength, http.StatusBadRequest)

		return
	}

	guid := uuid.New().String()

	user := calltypes.User{
		GUID:      guid,
		Email:     requestPayload.Email,
		FirstName: requestPayload.FirstName,
		LastName:  requestPayload.LastName,
		Password:  requestPayload.Password,
		Active:    requestPayload.Active,
	}

	id, err := s.Repo.Insert(user)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusBadRequest)

		return
	}

	payload := calltypes.JSONResponse{
		Error:   false,
		Message: fmt.Sprintf("Successfully created new user, id: %d", id),
	}

	err = httputils.WriteJSON(w, http.StatusOK, payload)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusBadRequest)

		return
	}
}

// Provide
// @Summary Get new token pair
// @Description Generates new access and refresh tokens for user
// @Tags Authentication
// @Produce json
// @Param id path string true "User GUID"
// @Success 200 {object} calltypes.JSONResponse
// @Failure 400 {object} calltypes.ErrorResponse
// @Failure 500 {object} calltypes.ErrorResponse
// @Router /provide/{id} [get].
func (s *RewardService) Provide(w http.ResponseWriter, r *http.Request) {
	guid, err := GetGUIDFromURL(r, "id")
	if err != nil {
		httputils.ErrorJSON(w, errormsg.ErrInvalidID, http.StatusBadRequest)

		return
	}

	tokenService := token.NewTokenService()

	ip := GetClientIP(r)
	if ip == "" {
		httputils.ErrorJSON(w, errormsg.ErrInvalidIP, http.StatusBadRequest)

		return
	}

	accessToken, refreshToken, hashToken, err := tokenService.GenerateTokens(ip, r.UserAgent(), guid)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusInternalServerError)

		return
	}

	claims, err := s.ParseAccessToken(accessToken)

	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	err = s.Repo.UpdateRefreshToken(guid, claims.PairID, hashToken)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusInternalServerError)

		return
	}

	s.setAuthCookies(w, accessToken, refreshToken)

	payload := calltypes.JSONResponse{
		Error:   false,
		Message: "Tokens has been successfully provided",
	}

	err = httputils.WriteJSON(w, http.StatusOK, payload, nil)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusBadRequest)

		return
	}
}

// Refresh
// @Summary Refresh token pair
// @Description Generates new tokens using valid refresh token
// @Tags Authentication
// @Produce json
// @Success 200 {object} calltypes.JSONResponse
// @Failure 401 {object} calltypes.ErrorResponse
// @Failure 403 {object} calltypes.ErrorResponse
// @Security ApiKeyAuth
// @Router /refresh [get].
func (s *RewardService) Refresh(w http.ResponseWriter, r *http.Request) { //nolint: funlen
	accessTokenReceived, err := (r.Cookie("accessToken"))
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	guid, err := ExtractGUIDFromToken(accessTokenReceived.Value)
	if err != nil {
		httputils.ErrorJSON(w, errormsg.ErrExtractGUIDFromToken, http.StatusInternalServerError)

		return
	}

	refreshCookie, err := r.Cookie("refreshToken")
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	ip := GetClientIP(r)

	claims, err := s.ParseAccessToken(accessTokenReceived.Value)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	if claims.IP != ip {
		s.sendIPChangeWebhook(claims.GUID, claims.IP, ip)
	}

	if claims.UserAgent != r.UserAgent() {
		s.Logout(w, r)
		fmt.Println("User agent has been changed, forced logout")

		return
	}

	ok, err := s.Repo.ValidateRefreshToken(refreshCookie.Value, claims.PairID, guid)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	if !ok {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	tokenService := token.NewTokenService()

	accessToken, refreshToken, hashToken, err := tokenService.GenerateTokensWithPairID(ip, r.UserAgent(), guid, claims.PairID)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusInternalServerError)

		return
	}

	err = s.Repo.UpdateRefreshToken(guid, claims.PairID, hashToken)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusInternalServerError)

		return
	}

	s.setAuthCookies(w, accessToken, refreshToken)

	payload := calltypes.JSONResponse{
		Error:   false,
		Message: "Tokens has been successfully refreshed",
	}

	err = httputils.WriteJSON(w, http.StatusOK, payload, nil)
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusBadRequest)

		return
	}
}

func (s *RewardService) sendIPChangeWebhook(guid, oldIP, newIP string) {
	webhookURL := os.Getenv("IP_CHANGE_WEBHOOK_URL")
	if webhookURL == "" {
		return
	}

	payload := map[string]interface{}{
		"event":     "ip_change_detected",
		"guid":      guid,
		"old_ip":    oldIP,
		"new_ip":    newIP,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("failed to marshall json data: %v", err)

		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData)) //nolint: gosec, noctx
	if err != nil {
		log.Printf("Failed to send IP change webhook: %v", err)

		return
	}
	defer resp.Body.Close()
}

func ExtractGUIDFromToken(tokenString string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("error during parsing jwt token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if guid, ok := claims["guid"].(string); ok {
			return guid, nil
		}

		return "", errormsg.ErrEmptyGUID
	}

	return "", errormsg.ErrEmptyGUID
}

// Logout
// @Summary Logout user
// @Description Invalidates user's refresh token and clears cookies
// @Tags Authentication
// @Produce json
// @Success 200 {object} calltypes.JSONResponse
// @Failure 401 {object} calltypes.ErrorResponse
// @Security ApiKeyAuth
// @Router /logout [get].
func (s *RewardService) Logout(w http.ResponseWriter, r *http.Request) {
	accessTokenReceived, err := (r.Cookie("accessToken"))
	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusUnauthorized)

		return
	}

	guid, err := ExtractGUIDFromToken(accessTokenReceived.Value)
	if err != nil {
		httputils.ErrorJSON(w, errormsg.ErrExtractGUIDFromToken, http.StatusInternalServerError)

		return
	}

	err = s.Repo.DeleteRefreshToken(guid)
	if err != nil {
		httputils.ErrorJSON(w, errormsg.ErrDeleteRefreshToken, http.StatusInternalServerError)

		return
	}

	ClearAuthCookies(w)

	payload := calltypes.JSONResponse{
		Error:   false,
		Message: "Successfully logged out",
	}
	err = httputils.WriteJSON(w, http.StatusOK, payload)

	if err != nil {
		httputils.ErrorJSON(w, err, http.StatusBadRequest)

		return
	}
}

func ClearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "accessToken",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}

func (s *RewardService) setAuthCookies(w http.ResponseWriter, access, refresh string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "accessToken",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(consts.AccessTokenExpireTime),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(consts.RefreshTokenExpireTime),
	})
}
