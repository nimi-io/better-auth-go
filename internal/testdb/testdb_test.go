package testdb

import (
	"context"
	"testing"
)

func TestConnections(t *testing.T) {
	t.Run("postgres", func(t *testing.T) {
		if err := Postgres(t).Ping(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("mysql", func(t *testing.T) {
		if err := MySQL(t).Ping(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("sqlite", func(t *testing.T) {
		if err := SQLite(t).Ping(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("mongo", func(t *testing.T) {
		d, _ := Mongo(t)
		if _, err := d.Collection("x").InsertOne(context.Background(), map[string]any{"a": 1}); err != nil {
			t.Fatal(err)
		}
	})
}
