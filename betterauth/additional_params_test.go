package betterauth

import (
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
)

func TestJSKeyOrder(t *testing.T) {
	got := strings.Join(oauth2.JSKeyOrder([]string{"b", "10", "a", "2", "01", "4294967295", "0"}), ",")
	if want := "0,2,10,b,a,01,4294967295"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestSignInSocialKeepsAdditionalParamsOrder(t *testing.T) {
	env := socialEnv(t, nil)
	c := env.client()
	res := c.post("/sign-in/social", `{"provider":"github","additionalParams":{"zeta":"1","2":"two","alpha":"3"}}`)
	if res.Status != 200 {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
	u, _ := url.Parse(res.JSON(t)["url"].(string))
	if !strings.HasSuffix(u.RawQuery, "&2=two&zeta=1&alpha=3") {
		t.Fatalf("query %s", u.RawQuery)
	}
}
