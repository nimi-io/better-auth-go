// Package cli is the Better Auth command line interface (packages/cli upstream): migrate,
// generate, secret and info.
//
// Upstream loads the auth configuration from a TypeScript file. A Go program cannot do that,
// so the CLI is a library: embed it in a small binary of your own that builds the same
// *betterauth.Auth your server uses, and migrate/generate see the full configuration
// (plugins, additional fields, renamed models and columns):
//
//	// cmd/auth/main.go
//	func main() {
//		ctx := context.Background()
//		os.Exit(cli.Run(ctx, os.Args[1:], cli.Options{
//			NewAuth: func(ctx context.Context, command string) (*betterauth.Auth, error) {
//				return myapp.NewAuth() // the same constructor the server uses
//			},
//		}))
//	}
//
//	$ go run ./cmd/auth migrate --yes
//	$ go run ./cmd/auth generate --output migrations/
//
// Options.Auth can carry an already constructed instance instead of NewAuth; NewAuth is
// preferred because "secret" never calls it and "info" reports its error instead of
// failing. The standalone github.com/nimi-io/better-auth-go/cmd/better-auth binary wraps Run
// for the default schema and a --database-url flag.
//
// Commands mirror upstream's messages, prompts and exit codes:
//
//	migrate   [-c|--cwd dir] [-y|--yes]                                     apply pending schema changes
//	generate  [-c|--cwd dir] [--output path] [--adapter id] [-y|--yes]     write the migration SQL to a file
//	secret                                                                   print a random BETTER_AUTH_SECRET
//	info      [--cwd dir] [-j|--json] [-c|--copy]                          print system and configuration details
//
// Migrations require an adapter implementing adapter.Migrator (the SQL adapter); other
// adapters get upstream's "not supported" messages.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
)

// ModulePath is the import path of this module (used to find its version in build info).
const ModulePath = "github.com/nimi-io/better-auth-go"

// ErrNoConfig marks a missing configuration (upstream's "No configuration file found"):
// migrate and generate print the message and exit with status 0, like upstream.
var ErrNoConfig = errors.New("no Better Auth configuration found")

type noConfigError struct{ msg string }

func (e *noConfigError) Error() string        { return e.msg }
func (e *noConfigError) Is(target error) bool { return target == ErrNoConfig }

// NoConfig returns an error that matches ErrNoConfig and prints as msg. NewAuth returns it
// when there is nothing to configure (e.g. no database URL).
func NoConfig(msg string) error { return &noConfigError{msg: msg} }

// Options configure Run.
type Options struct {
	// Auth is the Better Auth instance the commands operate on.
	Auth *betterauth.Auth
	// NewAuth builds the instance on demand (used when Auth is nil). command is the
	// subcommand being run ("migrate", "generate" or "info").
	NewAuth func(ctx context.Context, command string) (*betterauth.Auth, error)
	// Flags registers extra flags on the migrate, generate and info commands before they
	// are parsed (e.g. --database-url); NewAuth can read the bound values. A flag registered
	// here replaces a built-in flag of the same name.
	Flags func(command string, fs *flag.FlagSet)
	// Dialect reports the SQL dialect shown by info when the adapter has no Dialect()
	// method (optional; called after NewAuth).
	Dialect func() string

	// Stdin, Stdout and Stderr default to the process streams.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Now is the clock used for generated file names (default time.Now).
	Now func() time.Time
	// ProgramName is used in usage and hints (default "better-auth").
	ProgramName string
	// Version is printed by --version (default: this module's version from build info,
	// falling back to betterauth.Version).
	Version string
	// Color forces colored output on or off; by default color is used when Stdout is a
	// terminal and NO_COLOR is unset.
	Color *bool
}

type runner struct {
	opts   Options
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
	in     *bufio.Reader
	now    func() time.Time
	name   string
	st     styles
	auth   *betterauth.Auth
}

// command is a subcommand.
type command struct {
	name    string
	desc    string
	options []option
	run     func(r *runner, fs *flag.FlagSet) int
	// config reports whether the command loads the auth configuration (and receives
	// Options.Flags).
	config bool
}

// option describes a flag for parsing and help output.
type option struct {
	short, long string
	arg         string // non-empty for value flags
	desc        string
	def         string
}

var unported = map[string]string{
	"init":         "scaffolds a TypeScript project",
	"ai":           "installs AI editor rules for TypeScript projects",
	"login":        "authenticates against the Better Auth infrastructure dashboard",
	"logout":       "authenticates against the Better Auth infrastructure dashboard",
	"mcp":          "configures MCP servers for editors",
	"upgrade":      "upgrades npm packages",
	"create-admin": "is not ported yet",
	"check":        "is not ported yet",
}

func commands() []*command {
	return []*command{migrateCommand(), generateCommand(), secretCommand(), infoCommand()}
}

// Run executes the CLI with args (without the program name) and returns the exit status.
func Run(ctx context.Context, args []string, opts Options) int {
	if ctx == nil {
		ctx = context.Background()
	}
	r := &runner{opts: opts, ctx: ctx, auth: opts.Auth}
	r.stdout = opts.Stdout
	if r.stdout == nil {
		r.stdout = os.Stdout
	}
	r.stderr = opts.Stderr
	if r.stderr == nil {
		r.stderr = os.Stderr
	}
	stdin := opts.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	r.in = bufio.NewReader(stdin)
	r.now = opts.Now
	if r.now == nil {
		r.now = time.Now
	}
	r.name = opts.ProgramName
	if r.name == "" {
		r.name = "better-auth"
	}
	r.st = newStyles(useColor(opts.Color, r.stdout))

	cmds := commands()
	if len(args) == 0 {
		r.printHelp(r.stdout, cmds)
		return 0
	}
	first := args[0]
	switch first {
	case "-h", "--help":
		r.printHelp(r.stdout, cmds)
		return 0
	case "-V", "--version":
		fmt.Fprintln(r.stdout, r.version())
		return 0
	case "help":
		if len(args) > 1 {
			for _, c := range cmds {
				if c.name == args[1] {
					fs := r.flagSet(c)
					r.printCommandHelp(r.stdout, c, fs)
					return 0
				}
			}
			fmt.Fprintf(r.stderr, "error: unknown command '%s'\n", args[1])
			return 1
		}
		r.printHelp(r.stdout, cmds)
		return 0
	}
	if strings.HasPrefix(first, "-") {
		fmt.Fprintf(r.stderr, "error: unknown option '%s'\n", first)
		return 1
	}
	for _, c := range cmds {
		if c.name != first {
			continue
		}
		fs := r.flagSet(c)
		rest := args[1:]
		if fs.Lookup("deprecated-y") != nil {
			rest = preprocess(rest)
		}
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				r.printCommandHelp(r.stdout, c, fs)
				return 0
			}
			fmt.Fprintf(r.stderr, "error: %v\n", err)
			return 1
		}
		if fs.NArg() > 0 {
			fmt.Fprintf(r.stderr, "error: too many arguments for '%s'. Expected 0 arguments but got %d.\n", c.name, fs.NArg())
			return 1
		}
		return c.run(r, fs)
	}
	if why, ok := unported[first]; ok {
		fmt.Fprintf(r.stderr, "error: the '%s' command is not available in the Go CLI (upstream it %s).\n", first, why)
		return 1
	}
	fmt.Fprintf(r.stderr, "error: unknown command '%s'\n", first)
	return 1
}

// preprocess maps the deprecated "--y" flag to an internal name: Go's flag package treats
// "-y" and "--y" alike, but upstream distinguishes them.
func preprocess(args []string) []string {
	out := make([]string, 0, len(args))
	for i, a := range args {
		if a == "--" {
			return append(out, args[i:]...)
		}
		if a == "--y" || strings.HasPrefix(a, "--y=") {
			a = "--deprecated-y" + strings.TrimPrefix(a, "--y")
		}
		out = append(out, a)
	}
	return out
}

func (r *runner) flagSet(c *command) *flag.FlagSet {
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	if c.config && r.opts.Flags != nil {
		r.opts.Flags(c.name, fs)
	}
	for _, o := range c.options {
		names := []string{o.long}
		if o.short != "" {
			names = append(names, o.short)
		}
		for _, n := range names {
			if fs.Lookup(n) != nil {
				continue // overridden by Options.Flags
			}
			if o.arg != "" {
				fs.String(n, o.def, o.desc)
			} else {
				fs.Bool(n, false, o.desc)
			}
		}
	}
	return fs
}

// str returns the value of the first of names that was set on the command line, else the
// default of the first defined one (short and long spellings are separate flags).
func str(fs *flag.FlagSet, names ...string) string {
	for _, n := range names {
		if set(fs, n) {
			return fs.Lookup(n).Value.String()
		}
	}
	for _, n := range names {
		if f := fs.Lookup(n); f != nil {
			return f.Value.String()
		}
	}
	return ""
}

func boolean(fs *flag.FlagSet, names ...string) bool {
	for _, n := range names {
		if f := fs.Lookup(n); f != nil && f.Value.String() == "true" {
			return true
		}
	}
	return false
}

func set(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func (r *runner) printHelp(w io.Writer, cmds []*command) {
	fmt.Fprintf(w, "Usage: %s [options] [command]\n\nBetter Auth CLI\n\nOptions:\n", r.name)
	fmt.Fprintf(w, "  %-22s %s\n", "-V, --version", "output the version number")
	fmt.Fprintf(w, "  %-22s %s\n", "-h, --help", "display help for command")
	fmt.Fprintf(w, "\nCommands:\n")
	for _, c := range cmds {
		label := c.name
		if len(c.options) > 0 || c.config {
			label += " [options]"
		}
		fmt.Fprintf(w, "  %-22s %s\n", label, c.desc)
	}
	fmt.Fprintf(w, "  %-22s %s\n", "help [command]", "display help for command")
}

func (r *runner) printCommandHelp(w io.Writer, c *command, fs *flag.FlagSet) {
	fmt.Fprintf(w, "Usage: %s %s [options]\n\n", r.name, c.name)
	if c.desc != "" {
		fmt.Fprintf(w, "%s\n\n", c.desc)
	}
	fmt.Fprintf(w, "Options:\n")
	known := map[string]bool{"deprecated-y": true}
	type row struct{ label, desc string }
	var rows []row
	for _, o := range c.options {
		known[o.long] = true
		if o.short != "" {
			known[o.short] = true
		}
		if o.long == "deprecated-y" {
			rows = append(rows, row{"--y", o.desc})
			continue
		}
		label := "--" + o.long
		if o.short != "" {
			label = "-" + o.short + ", " + label
		}
		if o.arg != "" {
			label += " <" + o.arg + ">"
		}
		desc := o.desc
		if f := fs.Lookup(o.long); f != nil && f.Usage != o.desc {
			desc = f.Usage // replaced by Options.Flags
		}
		if o.def != "" {
			desc += fmt.Sprintf(" (default: %q)", o.def)
		}
		rows = append(rows, row{label, desc})
	}
	var extra []row
	fs.VisitAll(func(f *flag.Flag) {
		if known[f.Name] {
			return
		}
		label := "--" + f.Name
		if _, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok {
			label += " <" + f.Name + ">"
		}
		extra = append(extra, row{label, f.Usage})
	})
	sort.Slice(extra, func(i, j int) bool { return extra[i].label < extra[j].label })
	rows = append(rows, extra...)
	rows = append(rows, row{"-h, --help", "display help for command"})
	width := 0
	for _, rw := range rows {
		if len(rw.label) > width {
			width = len(rw.label)
		}
	}
	for _, rw := range rows {
		fmt.Fprintf(w, "  %-*s  %s\n", width, rw.label, rw.desc)
	}
}

func (r *runner) version() string {
	if r.opts.Version != "" {
		return r.opts.Version
	}
	if v := moduleVersion(); v != "" && v != "(devel)" {
		return strings.TrimPrefix(v, "v")
	}
	return betterauth.Version
}

// moduleVersion returns this module's version from the build info ("" if unknown).
func moduleVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if bi.Main.Path == ModulePath {
		return bi.Main.Version
	}
	for _, d := range bi.Deps {
		if d.Path == ModulePath {
			if d.Replace != nil && d.Replace.Version != "" {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	return ""
}

// loadAuth returns the configured instance.
func (r *runner) loadAuth(command string) (*betterauth.Auth, error) {
	if r.auth != nil {
		return r.auth, nil
	}
	if r.opts.NewAuth == nil {
		return nil, NoConfig("No Better Auth instance configured. Pass cli.Options.Auth or cli.Options.NewAuth to cli.Run.")
	}
	a, err := r.opts.NewAuth(r.ctx, command)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, NoConfig("No Better Auth instance configured: NewAuth returned nil.")
	}
	r.auth = a
	return a, nil
}

// fail reports an unexpected error like upstream's top-level handler and returns 1.
func (r *runner) fail(err error) int {
	fmt.Fprintf(r.stderr, "Error running Better Auth CLI: %v\n", err)
	return 1
}

// confirm asks a yes/no question (prompts' "confirm" type). Anything but y/yes, including
// EOF, answers no.
func (r *runner) confirm(message string) bool {
	fmt.Fprintf(r.stdout, "%s %s %s ", r.st.cyan("?"), r.st.bold(message), r.st.gray("› (y/N)"))
	line, err := r.in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(r.stdout)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "true":
		return true
	}
	return false
}

func checkCwd(stderr io.Writer, cwd string) (string, bool) {
	abs, err := absPath(cwd)
	if err != nil {
		fmt.Fprintf(stderr, "The directory \"%s\" does not exist.\n", cwd)
		return "", false
	}
	if _, err := os.Stat(abs); err != nil {
		fmt.Fprintf(stderr, "The directory \"%s\" does not exist.\n", abs)
		return "", false
	}
	return abs, true
}
