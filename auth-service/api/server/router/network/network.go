package network

import (
	"github.com/go-chi/chi/v5"
	"net/http"

	"auth-service/api/server/middleware"
	"auth-service/internal/service"
)

// SetupRoutes set up the Routes.
func SetupRoutes(svc *service.RewardService) http.Handler {
	r := chi.NewRouter()

	r.Group(func(secure chi.Router) {
		secure.Use(middleware.Auth())

		secure.Get("/refresh", svc.Refresh)
		secure.Get("/getguid", svc.GetGUID)
		secure.Get("/logout", svc.Logout)
	})

	r.Post("/registrate", svc.Registrate)
	r.Get("/provide/{id}", svc.Provide)

	return r
}
