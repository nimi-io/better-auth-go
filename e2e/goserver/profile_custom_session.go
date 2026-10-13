package main

import (
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/customsession"
	"github.com/nimi-io/better-auth-go/plugins/multisession"
)

func init() {
	profiles["custom-session"] = func(cfg *betterauth.Config, _ profileEnv) {
		fn := func(_ *betterauth.EndpointContext, s *betterauth.SessionWithUser) (any, error) {
			parts := strings.Split(s.User.Name, " ")
			user := jsonx.O("firstName", parts[0])
			if len(parts) > 1 {
				user.Set("lastName", parts[1])
			}
			user.Set("email", s.User.Email)
			return jsonx.O("user", user, "newData", jsonx.O("message", "Hello, World!"), "session", s.Session), nil
		}
		cfg.Plugins = append(cfg.Plugins, multisession.New(),
			customsession.New(fn, customsession.Options{ShouldMutateListDeviceSessionsEndpoint: true}))
	}
}
