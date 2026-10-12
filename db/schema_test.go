package db

import "testing"

func TestGetAuthTablesDefaultsRenamesAndPlugins(t *testing.T) {
	s := GetAuthTables(Options{})
	var keys []string
	for _, tb := range s.Tables {
		keys = append(keys, tb.Key)
	}
	if got := len(keys); got != 4 || keys[0] != "user" || keys[3] != "verification" {
		t.Fatalf("default tables: %v", keys)
	}
	s = GetAuthTables(Options{
		User:                ModelOptions{ModelName: "users", Fields: map[string]string{"emailVerified": "email_verified"}, AdditionalFields: []Field{{Name: "role", Type: TypeString}}},
		Plugins:             [][]PluginTable{{{Key: "user", Fields: []Field{{Name: "banned", Type: TypeBoolean}}}, {Key: "twoFactor", Fields: []Field{{Name: "secret", Type: TypeString}}}}},
		HasSecondaryStorage: true,
		RateLimitInDatabase: true,
	})
	u := s.Table("user")
	if u.ModelName != "users" {
		t.Fatalf("model rename: %s", u.ModelName)
	}
	f, _ := u.Field("emailVerified")
	if f.Column() != "email_verified" {
		t.Fatalf("field rename: %s", f.Column())
	}
	if last := u.Fields[len(u.Fields)-1].Name; last != "role" || u.Fields[len(u.Fields)-2].Name != "banned" {
		t.Fatalf("plugin fields then additional fields expected, got last=%s", last)
	}
	if s.Table("session") != nil || s.Table("verification") != nil {
		t.Fatal("secondary storage without storeInDatabase should drop session/verification tables")
	}
	if s.Table("twoFactor") == nil || s.Table("rateLimit") == nil {
		t.Fatal("plugin and rateLimit tables missing")
	}
}
