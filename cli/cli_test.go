package cli

import (
	"context"
	"errors"
	"flag"
	"regexp"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-h"}, {"help"}} {
		r := run(t, Options{}, "", args...)
		if r.code != 0 {
			t.Fatalf("%v: exit %d", args, r.code)
		}
		contains(t, r.stdout, "Usage: better-auth [options] [command]")
		contains(t, r.stdout, "migrate [options]")
		contains(t, r.stdout, "generate [options]")
		contains(t, r.stdout, "secret")
		contains(t, r.stdout, "Display system and Better Auth configuration information")
	}
	r := run(t, Options{Version: "9.9.9"}, "", "--version")
	if r.code != 0 || r.stdout != "9.9.9\n" {
		t.Fatalf("version: %d %q", r.code, r.stdout)
	}
	r = run(t, Options{}, "", "-V")
	if r.code != 0 || r.stdout == "" {
		t.Fatalf("-V: %d %q", r.code, r.stdout)
	}
}

func TestCommandHelp(t *testing.T) {
	r := run(t, Options{ProgramName: "auth"}, "", "migrate", "--help")
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stdout, "Usage: auth migrate [options]")
	contains(t, r.stdout, "-c, --cwd <cwd>")
	contains(t, r.stdout, "-y, --yes")
	contains(t, r.stdout, "--y ")
	contains(t, r.stdout, "(deprecated) same as --yes")

	r = run(t, Options{Flags: func(_ string, fs *flag.FlagSet) {
		fs.String("database-url", "", "the database URL")
	}}, "", "help", "generate")
	contains(t, r.stdout, "--database-url <database-url>  the database URL")
	contains(t, r.stdout, "--output <output>")
}

func TestUnknownCommandsAndOptions(t *testing.T) {
	r := run(t, Options{}, "", "frobnicate")
	if r.code != 1 || r.stderr != "error: unknown command 'frobnicate'\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	r = run(t, Options{}, "", "--frob")
	if r.code != 1 || r.stderr != "error: unknown option '--frob'\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	r = run(t, Options{}, "", "migrate", "--frob")
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stderr, "error: flag provided but not defined: -frob")
	r = run(t, Options{}, "", "init")
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stderr, "the 'init' command is not available in the Go CLI")
}

func TestSecret(t *testing.T) {
	r := run(t, Options{}, "", "secret")
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	re := regexp.MustCompile(`^\nAdd the following to your \.env file:\n# Auth Secret\nBETTER_AUTH_SECRET=[0-9a-f]{64}\n$`)
	if !re.MatchString(r.stdout) {
		t.Fatalf("unexpected output %q", r.stdout)
	}
	again := run(t, Options{}, "", "secret")
	if again.stdout == r.stdout {
		t.Fatal("secret is not random")
	}
}

func TestSecretDoesNotLoadConfig(t *testing.T) {
	called := false
	r := run(t, Options{NewAuth: func(context.Context, string) (*betterauth.Auth, error) {
		called = true
		return nil, errors.New("boom")
	}}, "", "secret")
	if r.code != 0 || called {
		t.Fatalf("exit %d, NewAuth called %v", r.code, called)
	}
}

func TestColor(t *testing.T) {
	on := true
	r := run(t, Options{Color: &on}, "", "secret")
	contains(t, r.stdout, "\x1b[90m# Auth Secret\x1b[0m")
	contains(t, r.stdout, "\x1b[32m\nBETTER_AUTH_SECRET=")
}

func TestPreprocessDeprecatedY(t *testing.T) {
	got := preprocess([]string{"-y", "--y", "--y=false", "--", "--y"})
	want := []string{"-y", "--deprecated-y", "--deprecated-y=false", "--", "--y"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestFlagsHookAndNewAuth(t *testing.T) {
	var url string
	var gotCommand string
	executed := 0
	fake := &fakeSQL{plan: pendingPlan(&executed)}
	opts := Options{
		Flags: func(_ string, fs *flag.FlagSet) {
			fs.StringVar(&url, "database-url", "", "url")
		},
		NewAuth: func(_ context.Context, command string) (*betterauth.Auth, error) {
			gotCommand = command
			if url != "sqlite:test.db" {
				t.Fatalf("flag not parsed before NewAuth: %q", url)
			}
			return newAuth(t, betterauth.Config{Database: fakeFactory(fake)}), nil
		},
	}
	r := run(t, opts, "", "migrate", "--database-url", "sqlite:test.db", "--yes")
	if r.code != 0 || gotCommand != "migrate" || executed != 1 {
		t.Fatalf("exit %d command %q executed %d\n%s%s", r.code, gotCommand, executed, r.stdout, r.stderr)
	}
}
