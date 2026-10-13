package openapi

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

func TestReferencePage(t *testing.T) {
	a := newInstance(t, nil, New(Options{Path: "/docs", Theme: ThemeMoon, Nonce: "abc"}))
	res, err := a.API.Call(context.Background(), "openAPIReference", betterauth.CallInput{})
	if err != nil {
		t.Fatal(err)
	}
	raw := res.Data.(*betterauth.Response)
	if raw.Header.Get("Content-Type") != "text/html" {
		t.Fatalf("content type %q", raw.Header.Get("Content-Type"))
	}
	body := string(raw.Body)
	for _, want := range []string{`theme: "moon"`, `<script nonce="abc">`, `"openapi":"3.1.1"`, "data:image/svg+xml;utf8,%3Csvg"} {
		if !containsSub(body, want) {
			t.Fatalf("page lacks %q", want)
		}
	}
	d := newInstance(t, nil, New(Options{DisableDefaultReference: true}))
	if _, err := d.API.Call(context.Background(), "openAPIReference", betterauth.CallInput{}); err == nil {
		t.Fatal("expected NOT_FOUND")
	} else if e, ok := betterauth.AsAPIError(err); !ok || e.StatusCode != 404 {
		t.Fatalf("err %v", err)
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
