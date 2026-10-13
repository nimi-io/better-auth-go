package main

import (
	"database/sql"
	"log"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/username"
)

// Username profile (mirrors e2e/servers/profiles/username.mjs).
func init() {
	profiles["username"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Database = pluginSQLite()
		cfg.Plugins = append(cfg.Plugins, username.New(username.Options{MinUsernameLength: 4}))
	}
}

// pluginSQLite opens a private in-memory SQLite database. The TypeScript server uses
// better-sqlite3 (":memory:"), which returns never-written plugin columns as null; the Go
// memory adapter omits them, so the username/phone-number/siwe/captcha/haveibeenpwned
// profiles use SQLite too (the tests start the Go server with MIGRATE=1).
func pluginSQLite() adapter.Factory {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	return sqladapter.New(conn, sqladapter.Config{})
}
