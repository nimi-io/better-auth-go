package mongodb

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// Cross-implementation tests: the TypeScript adapter of better-auth 1.7.7 (driven by
// e2e/scripts/mongo-compat.mjs) and this adapter share one database. Each side reads the
// rows the other wrote, and the stored documents of both must have the same keys, key
// order and BSON types.

func runCompat(t *testing.T, command string, input map[string]any) map[string]any {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; skipping the TypeScript cross-compatibility check")
	}
	e2e, _ := filepath.Abs(filepath.Join("..", "..", "e2e"))
	if _, err := os.Stat(filepath.Join(e2e, "node_modules", "mongodb")); err != nil {
		t.Skip("e2e/node_modules/mongodb is missing; run `npm install` in e2e/ to enable the TypeScript cross-compatibility check")
	}
	if _, err := os.Stat(filepath.Join(e2e, "node_modules", "better-auth")); err != nil {
		t.Skip("e2e/node_modules/better-auth is missing; run `npm install` in e2e/")
	}
	b, _ := json.Marshal(input)
	cmd := exec.Command(node, filepath.Join("scripts", "mongo-compat.mjs"), command)
	cmd.Dir = e2e
	cmd.Stdin = bytes.NewReader(b)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("mongo-compat.mjs %s: %v\n%s", command, err, stderr.String())
	}
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("mongo-compat.mjs output: %v\n%s", err, stdout.String())
	}
	return out
}

func mongoURI() string {
	if uri := os.Getenv("BA_TEST_MONGO_URI"); uri != "" {
		return uri
	}
	return testdb.DefaultMongoURI
}

func TestCrossCompatWithTypeScriptAdapter(t *testing.T) {
	for _, mode := range []string{"default", "uuid"} {
		t.Run(mode, func(t *testing.T) {
			database, _ := testdb.Mongo(t)
			input := map[string]any{"uri": mongoURI(), "db": database.Name(), "idMode": mode}
			ts := runCompat(t, "write", input)

			idMode := adapter.IDDefault
			if mode == "uuid" {
				idMode = adapter.IDUUID
			}
			a := mustAdapter(t, New(database, Config{}), adapter.Options{
				Schema: schemaOf(db.Options{RateLimitInDatabase: true}), IDMode: idMode, Joins: true})
			stamp := time.Date(2024, 1, 2, 3, 4, 5, 678e6, time.UTC)
			expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			user, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{
				"name": "Go User", "email": "go@example.com", "emailVerified": true, "image": nil, "createdAt": stamp, "updatedAt": stamp}})
			if err != nil {
				t.Fatal(err)
			}
			mustCreate := func(model string, data adapter.Record) adapter.Record {
				t.Helper()
				r, err := a.Create(ctx, adapter.CreateInput{Model: model, Data: data})
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			mustCreate("session", adapter.Record{"userId": user["id"], "token": "go-token", "expiresAt": expires, "ipAddress": "127.0.0.1", "createdAt": stamp, "updatedAt": stamp})
			mustCreate("account", adapter.Record{"accountId": user["id"], "providerId": "credential", "userId": user["id"], "password": "go-hash", "createdAt": stamp, "updatedAt": stamp})
			mustCreate("verification", adapter.Record{"identifier": "go-identifier", "value": "go-value", "expiresAt": expires, "createdAt": stamp, "updatedAt": stamp})
			mustCreate("rateLimit", adapter.Record{"key": "go-key", "count": int64(1), "lastRequest": int64(1700000000000)})

			// 1. identical document shape (keys, order, BSON types)
			idOf := func(rec map[string]any) any {
				id := rec["id"].(string)
				if mode == "uuid" {
					b, _ := parseUUID(id)
					return bson.Binary{Subtype: bson.TypeBinaryUUID, Data: b}
				}
				return oid(t, id)
			}
			for _, model := range []string{"user", "session", "account", "verification", "rateLimit"} {
				tsRec := ts[model].(map[string]any)
				tsDoc := rawDoc(t, database, model, bson.D{{Key: "_id", Value: idOf(tsRec)}})
				var goDoc bson.Raw
				cur, err := database.Collection(model).Find(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$ne", Value: idOf(tsRec)}}}})
				if err != nil {
					t.Fatal(err)
				}
				if cur.Next(ctx) {
					goDoc = append(bson.Raw(nil), cur.Current...)
				}
				_ = cur.Close(ctx)
				if goDoc == nil {
					t.Fatalf("%s: Go document not found", model)
				}
				if g, w := docTypes(t, goDoc), docTypes(t, tsDoc); g != w {
					t.Errorf("%s document differs\n   go: %s\n   ts: %s", model, g, w)
				} else {
					t.Logf("%s: %s", model, g)
				}
			}

			// 2. Go reads rows written by TypeScript
			tsUser := ts["user"].(map[string]any)
			got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: tsUser["id"]}},
				Join: map[string]adapter.Join{"session": {}, "account": {}}})
			if err != nil || got == nil {
				t.Fatalf("go findOne ts user: %v %v", got, err)
			}
			if got["name"] != "TS User" || got["email"] != "ts@example.com" || got["emailVerified"] != true || !got["createdAt"].(time.Time).Equal(stamp) {
				t.Errorf("ts user read by go: %v", got)
			}
			if ss := got["session"].([]adapter.Record); len(ss) != 1 || ss[0]["token"] != "ts-token" || ss[0]["userId"] != tsUser["id"] || !ss[0]["expiresAt"].(time.Time).Equal(expires) {
				t.Errorf("ts sessions joined by go: %v", got["session"])
			}
			if as := got["account"].([]adapter.Record); len(as) != 1 || as[0]["password"] != "ts-hash" {
				t.Errorf("ts accounts joined by go: %v", got["account"])
			}
			s, err := a.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "token", Value: "ts-token"}}, Join: map[string]adapter.Join{"user": {}}})
			if err != nil || s == nil || s["user"].(adapter.Record)["id"] != tsUser["id"] {
				t.Errorf("ts session read by go: %v %v", s, err)
			}
			rl, err := a.IncrementOne(ctx, adapter.IncrementInput{Model: "rateLimit", Where: []adapter.Where{{Field: "key", Value: "ts-key"}}, Increment: map[string]float64{"count": 1}})
			if err != nil || rl["count"] != int64(2) || rl["lastRequest"] != int64(1700000000000) {
				t.Errorf("ts rateLimit incremented by go: %v %v", rl, err)
			}
			if v, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "identifier", Value: "ts-identifier"}}); err != nil || v["value"] != "ts-value" {
				t.Errorf("ts verification consumed by go: %v %v", v, err)
			}

			// 3. TypeScript reads rows written by Go
			read := runCompat(t, "read", map[string]any{
				"uri": mongoURI(), "db": database.Name(), "idMode": mode,
				"userId": user["id"], "email": "go@example.com", "token": "go-token", "identifier": "go-identifier", "rateLimitKey": "go-key"})
			ru := read["user"].(map[string]any)
			if ru["id"] != user["id"] || ru["name"] != "Go User" || ru["emailVerified"] != true || ru["createdAt"] != "2024-01-02T03:04:05.678Z" {
				t.Errorf("go user read by ts: %v", ru)
			}
			if ss := ru["session"].([]any); len(ss) != 1 || ss[0].(map[string]any)["token"] != "go-token" {
				t.Errorf("go sessions joined by ts: %v", ru["session"])
			}
			if as := ru["account"].([]any); len(as) != 1 || as[0].(map[string]any)["password"] != "go-hash" {
				t.Errorf("go accounts joined by ts: %v", ru["account"])
			}
			if ube, ok := read["userByEmail"].(map[string]any); !ok || ube["id"] != user["id"] {
				t.Errorf("insensitive lookup by ts: %v", read["userByEmail"])
			}
			if ss := read["sessions"].([]any); len(ss) != 1 || ss[0].(map[string]any)["userId"] != user["id"] || ss[0].(map[string]any)["expiresAt"] != "2030-01-01T00:00:00.000Z" {
				t.Errorf("go sessions found by ts (userId lookup): %v", read["sessions"])
			}
			if rs := read["session"].(map[string]any); rs["user"].(map[string]any)["id"] != user["id"] {
				t.Errorf("go session joined to user by ts: %v", rs)
			}
			if rv := read["verification"].(map[string]any); rv["value"] != "go-value" {
				t.Errorf("go verification read by ts: %v", rv)
			}
			if rr := read["rateLimit"].(map[string]any); rr["count"] != float64(2) || rr["lastRequest"] != float64(1700000000000) {
				t.Errorf("go rateLimit incremented by ts: %v", rr)
			}
			if up := read["updated"].(map[string]any); up["name"] != "Updated by TS" {
				t.Errorf("ts update of go user: %v", up)
			}
			after, _ := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: user["id"]}}})
			if after["name"] != "Updated by TS" || after["emailVerified"] != true {
				t.Errorf("go re-read after ts update: %v", after)
			}
			rlDoc := rawDoc(t, database, "rateLimit", bson.D{{Key: "key", Value: "go-key"}})
			if rlDoc.Lookup("count").Type != bson.TypeInt32 {
				t.Errorf("count type after ts increment: %v", rlDoc.Lookup("count").Type)
			}
		})
	}
}
