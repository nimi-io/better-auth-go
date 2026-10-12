// Example: Better Auth with Fiber (fasthttp), bridged through Fiber's net/http adaptor.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"

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

	app := fiber.New()
	app.All("/api/auth/*", adaptor.HTTPHandler(auth.Handler()))

	me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b, _ := betterauth.SessionFromContext(r.Context()).MarshalJSON()
		_, _ = w.Write(b)
	})
	app.Get("/api/me", adaptor.HTTPHandler(auth.RequireSession(me)))

	log.Fatal(app.Listen(":3000"))
}
