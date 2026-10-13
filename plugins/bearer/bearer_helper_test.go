package bearer_test

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
)

func bearerPlugin() *betterauth.Plugin { return bearer.New() }
