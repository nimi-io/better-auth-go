// Example: Better Auth with Gin.
package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// requireSession is a Gin middleware backed by Auth.ResolveSession.
func requireSession(auth *betterauth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		s, err := auth.ResolveSession(c.Writer, c.Request)
		if err != nil || s == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "code": "UNAUTHORIZED"})
			return
		}
		c.Set("session", s)
		c.Next()
	}
}

func main() {
	auth := betterauth.MustNew(betterauth.Config{
		BaseURL:          "http://localhost:3000",
		Secret:           os.Getenv("BETTER_AUTH_SECRET"),
		Database:         memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
	})

	r := gin.Default()
	r.Any("/api/auth/*path", gin.WrapH(auth.Handler()))
	r.GET("/api/me", requireSession(auth), func(c *gin.Context) {
		s, _ := c.Get("session")
		c.JSON(http.StatusOK, s)
	})
	_ = r.Run(":3000")
}
