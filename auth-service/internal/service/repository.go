package service

import (
	"auth-service/internal/postgres/repository"
	"net/http"
)

type RewardServiceInterface interface {
	Registrate(w http.ResponseWriter, r *http.Request)
	Refresh(w http.ResponseWriter, r *http.Request)
	Provide(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
	GetGUID(w http.ResponseWriter, r *http.Request)
	CheckRefreshToken(w http.ResponseWriter, r *http.Request)
}

type RewardService struct {
	RewardServiceInterface
	Repo   repository.Repository
	Client *http.Client
}
