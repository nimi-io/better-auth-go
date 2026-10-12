// Example: Better Auth with chi.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func main() {
	auth := betterauth.MustNew(betterauth.Config{
		BaseURL:          "http://localhost:3000",
		Secret:           os.Getenv("BETTER_AUTH_SECRET"),
		Database:         memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
	})

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	// Every request under /api/auth goes to Better Auth.
	r.Handle("/api/auth/*", auth.Handler())

	r.Group(func(r chi.Router) {
		r.Use(auth.RequireSession)
		r.Get("/api/me", func(w http.ResponseWriter, r *http.Request) {
			render.JSON(w, r, betterauth.SessionFromContext(r.Context()))
		})
	})

	log.Fatal(http.ListenAndServe(":3000", r))
}
