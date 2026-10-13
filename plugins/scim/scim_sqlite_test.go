package scim

// Port of upstream scim-sqlite.test.ts.

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	_ "modernc.org/sqlite"
)

const sqliteLegacyDDL = `
CREATE TABLE "scimUser" (
	"id" text PRIMARY KEY NOT NULL,
	"connectionId" text NOT NULL,
	"provisioningDomainId" text NOT NULL,
	"userId" text NOT NULL,
	"connectionUserKey" text NOT NULL,
	"userName" text NOT NULL,
	"userNameKey" text NOT NULL,
	"primaryEmail" text NOT NULL,
	"workEmailValueIndex" text NOT NULL,
	"emailValueIndex" text NOT NULL,
	"displayName" text NOT NULL,
	"formattedName" text NOT NULL,
	"givenName" text,
	"familyName" text,
	"serializedEmails" text NOT NULL,
	"externalId" text,
	"externalIdKey" text,
	"active" integer NOT NULL,
	"orderKey" text NOT NULL,
	"createdAt" integer NOT NULL,
	"updatedAt" integer NOT NULL
);
INSERT INTO "scimUser" (
	"id", "connectionId", "provisioningDomainId", "userId",
	"connectionUserKey", "userName", "userNameKey", "primaryEmail",
	"workEmailValueIndex", "emailValueIndex", "displayName",
	"formattedName", "givenName", "familyName", "serializedEmails",
	"active", "orderKey", "createdAt", "updatedAt"
) VALUES (
	'legacy-scim-user', 'legacy', 'legacy', 'legacy-user',
	'legacy:user', 'legacy@example.com', 'legacy:username',
	'legacy@example.com', '|legacy|', '|legacy|', 'Legacy User',
	'Legacy User', 'Legacy', 'User',
	'[{"value":"legacy@example.com","primary":true}]',
	1, 'legacy-order', 0, 0
);`

// sqliteOpen is new DatabaseSync(":memory:").
func sqliteOpen(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// sqliteCreateLegacyTable is createLegacySCIMUserTable.
func sqliteCreateLegacyTable(t *testing.T, conn *sql.DB) {
	t.Helper()
	for _, stmt := range strings.Split(sqliteLegacyDDL, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("legacy DDL: %v", err)
		}
	}
}

// sqliteLegacyAuth is createLegacySCIMAuth (no migrations run).
func sqliteLegacyAuth(t *testing.T, conn *sql.DB) *testEnv {
	t.Helper()
	a, err := betterauth.New(betterauth.Config{
		BaseURL:   testBaseURL,
		Secret:    testAuthSecret,
		Logger:    betterauth.NopLogger{},
		RateLimit: &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Database:  sqladapter.New(conn, sqladapter.Config{Transaction: betterauth.Bool(true)}),
		Plugins:   []*betterauth.Plugin{New(Options{Connections: []ConnectionOptions{staticConnection("legacy", "legacy-token")}})},
	})
	if err != nil {
		t.Fatalf("betterauth.New: %v", err)
	}
	return &testEnv{t: t, auth: a, sqlDB: conn}
}

func TestSQLite(t *testing.T) {
	t.Run("adds serializedAttributes as a nullable column that migrates populated legacy rows", func(t *testing.T) {
		conn := sqliteOpen(t)
		sqliteCreateLegacyTable(t, conn)
		e := sqliteLegacyAuth(t, conn)
		ctx := context.Background()

		plan, err := e.auth.PlanMigrations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		found := false
		for _, tc := range plan.ToBeAdded {
			if tc.Table != "scimUser" {
				continue
			}
			found = true
			for _, f := range tc.Fields {
				names = append(names, f.Name)
				if f.Name == "serializedAttributes" {
					if f.Type != "string" || f.Required == nil || *f.Required {
						t.Fatalf("serializedAttributes = type %q required %v", f.Type, f.Required)
					}
				}
			}
		}
		if !found || strings.Join(names, ",") != "serializedAttributes" {
			t.Fatalf("scimUser additions = %v (found %v)", names, found)
		}
		sqlText := strings.ToLower(plan.SQL())
		if !strings.Contains(sqlText, `add column "serializedattributes" text`) {
			t.Fatalf("migration SQL missing column: %s", sqlText)
		}
		if regexp.MustCompile(`add column "serializedattributes"[^;]*not null`).MatchString(sqlText) {
			t.Fatalf("serializedAttributes is NOT NULL: %s", sqlText)
		}
		if err := plan.Run(ctx); err != nil {
			t.Fatalf("runMigrations: %v", err)
		}

		res := e.request("GET", scimUsersURL+"/legacy-scim-user", nil, scimHeaders("legacy-token", false))
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		httpContractMustMatch(t, res.json(), map[string]any{
			"userName": "legacy@example.com",
			"name": map[string]any{
				"formatted": "Legacy User", "givenName": "Legacy", "familyName": "User",
			},
			"emails": []any{map[string]any{"value": "legacy@example.com", "primary": true}},
		})
	})

	t.Run("upgrades a populated legacy table and provisions a new user through the real HTTP endpoint", func(t *testing.T) {
		conn := sqliteOpen(t)
		sqliteCreateLegacyTable(t, conn)
		e := sqliteLegacyAuth(t, conn)
		if err := e.auth.RunMigrations(context.Background()); err != nil {
			t.Fatal(err)
		}
		res := e.request("POST", scimUsersURL, map[string]any{
			"schemas":     []any{httpContractUserSchema},
			"userName":    "upgraded@example.com",
			"displayName": "Upgraded User",
			"name": map[string]any{
				"formatted": "Ms. Upgraded User", "givenName": "Upgraded", "familyName": "User",
			},
			"emails": []any{map[string]any{"value": "upgraded@example.com", "type": "work", "primary": true}},
			"active": true,
		}, scimHeaders("legacy-token", true))
		if res.Status != 201 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		var formatted string
		var given, family sql.NullString
		var serializedEmails string
		var serializedAttributes sql.NullString
		err := conn.QueryRow(`SELECT "formattedName", "givenName", "familyName",
			"serializedEmails", "serializedAttributes"
			FROM "scimUser" WHERE "userName" = 'upgraded@example.com'`).
			Scan(&formatted, &given, &family, &serializedEmails, &serializedAttributes)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if formatted != "Ms. Upgraded User" || given.String != "Upgraded" || family.String != "User" {
			t.Fatalf("persisted names = %q %q %q", formatted, given.String, family.String)
		}
		var emails any
		if err := json.Unmarshal([]byte(serializedEmails), &emails); err != nil {
			t.Fatal(err)
		}
		wantEmails := []any{map[string]any{"value": "upgraded@example.com", "type": "work", "primary": true}}
		if httpContractJSON(emails) != httpContractJSON(wantEmails) {
			t.Fatalf("serializedEmails = %s", serializedEmails)
		}
		attrsText := serializedAttributes.String
		if !serializedAttributes.Valid {
			attrsText = "{}"
		}
		var attrs any
		if err := json.Unmarshal([]byte(attrsText), &attrs); err != nil {
			t.Fatal(err)
		}
		httpContractMustMatch(t, attrs, map[string]any{
			"schemas": []any{httpContractUserSchema},
			"name": map[string]any{
				"formatted": "Ms. Upgraded User", "givenName": "Upgraded", "familyName": "User",
			},
			"emails": wantEmails,
		})
	})

	t.Run("persists and queries canonical resources through a native transaction adapter", func(t *testing.T) {
		e := newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("sqlite-workforce", "sqlite-scim-token")}},
			envOptions{sqlite: true})
		headers := bearer("sqlite-scim-token")
		user := e.mustCall("createSCIMUser", betterauth.CallInput{
			Body: map[string]any{
				"schemas":  []any{httpContractUserSchema},
				"userName": "sqlite-user",
				"emails": []any{
					map[string]any{"value": "primary@example.com", "type": "home", "primary": true},
					map[string]any{"value": "first-work@example.com", "type": "other"},
					map[string]any{"value": "second-work@example.com", "type": "work"},
				},
			},
			Headers: headers,
		})
		users := e.mustCall("listSCIMUsers", betterauth.CallInput{
			Query:   map[string]any{"filter": `emails[type eq "work"].value eq "second-work@example.com"`},
			Headers: headers,
		})
		httpContractMustMatch(t, users, map[string]any{
			"totalResults": 1,
			"Resources":    []any{map[string]any{"id": user["id"]}},
		})
		group := e.mustCall("createSCIMGroup", betterauth.CallInput{
			Body: map[string]any{
				"schemas":     []any{httpContractGroupSchema},
				"displayName": "SQLite operators",
				"members":     []any{map[string]any{"value": user["id"], "type": "User"}},
			},
			Headers: headers,
		})
		httpContractMustMatch(t, group["members"], []any{map[string]any{"value": user["id"], "type": "User"}})
		if rows := e.rows("account"); len(rows) != 0 {
			t.Fatalf("accounts = %v", rows)
		}
	})
}
