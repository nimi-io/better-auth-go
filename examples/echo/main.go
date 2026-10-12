// Example: Better Auth with Echo.
package main

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v4"

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

	e := echo.New()
	e.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))

	// echo.WrapMiddleware adapts the net/http middleware.
	e.GET("/api/me", func(c echo.Context) error {
		return c.JSON(http.StatusOK, betterauth.SessionFromContext(c.Request().Context()))
	}, echo.WrapMiddleware(auth.RequireSession))

	e.Logger.Fatal(e.Start(":3000"))
}
