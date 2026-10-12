// Example: Better Auth with net/http.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

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

	app := http.NewServeMux()
	// Protected route: 401 unless a valid session cookie is present.
	app.Handle("/api/me", auth.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := betterauth.SessionFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s)
	})))

	// auth.Mount serves /api/auth/* and passes everything else to app.
	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", auth.Mount(app)))
}
