package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
)

func infoCommand() *command {
	return &command{
		name:   "info",
		desc:   "Display system and Better Auth configuration information",
		config: true,
		options: []option{
			{long: "cwd", arg: "cwd", desc: "The working directory"},
			{short: "j", long: "json", desc: "Output as JSON"},
			{short: "c", long: "copy", desc: "Copy output to clipboard (requires pbcopy/xclip)"},
		},
		run: (*runner).info,
	}
}

// reportedModule maps a module path (without a /vN suffix) to the name info reports.
type reportedModule struct{ name, path string }

// Go equivalents of upstream's framework and database client lists.
var (
	reportedFrameworks = []reportedModule{
		{"gin", "github.com/gin-gonic/gin"},
		{"echo", "github.com/labstack/echo"},
		{"fiber", "github.com/gofiber/fiber"},
		{"chi", "github.com/go-chi/chi"},
		{"gorilla/mux", "github.com/gorilla/mux"},
		{"hertz", "github.com/cloudwego/hertz"},
		{"huma", "github.com/danielgtaylor/huma"},
		{"connect", "connectrpc.com/connect"},
		{"grpc", "google.golang.org/grpc"},
	}
	reportedDatabases = []reportedModule{
		{"pgx", "github.com/jackc/pgx"},
		{"lib/pq", "github.com/lib/pq"},
		{"go-sql-driver/mysql", "github.com/go-sql-driver/mysql"},
		{"modernc.org/sqlite", "modernc.org/sqlite"},
		{"go-sqlite3", "github.com/mattn/go-sqlite3"},
		{"libsql", "github.com/tursodatabase/libsql-client-go"},
		{"go-libsql", "github.com/tursodatabase/go-libsql"},
		{"mongo-driver", "go.mongodb.org/mongo-driver"},
		{"gorm", "gorm.io/gorm"},
		{"ent", "entgo.io/ent"},
		{"bun", "github.com/uptrace/bun"},
		{"sqlx", "github.com/jmoiron/sqlx"},
		{"sqlc", "github.com/sqlc-dev/sqlc"},
		{"go-redis", "github.com/redis/go-redis"},
	}
)

var majorSuffix = func(p string) string {
	i := strings.LastIndex(p, "/v")
	if i < 0 {
		return p
	}
	for _, c := range p[i+2:] {
		if c < '0' || c > '9' {
			return p
		}
	}
	if i+2 == len(p) {
		return p
	}
	return p[:i]
}

func buildDeps(list []reportedModule) []any {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	var out []any
	for _, rm := range list {
		for _, d := range bi.Deps {
			if majorSuffix(d.Path) != rm.path {
				continue
			}
			v := d.Version
			if d.Replace != nil && d.Replace.Version != "" {
				v = d.Replace.Version
			}
			out = append(out, newObject().set("name", rm.name).set("version", v))
		}
	}
	return out
}

func goInfo() *object {
	env := os.Getenv("NODE_ENV")
	if env == "" {
		env = os.Getenv("GO_ENV")
	}
	if env == "" {
		env = "development"
	}
	return newObject().set("version", runtime.Version()).set("env", env)
}

// moduleInfo is the Go stand-in for upstream's package manager section: the main module of
// the running binary.
func moduleInfo() any {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return newObject().set("path", bi.Main.Path).set("version", orUnknown(bi.Main.Version)).set("goVersion", bi.GoVersion)
}

// dialectOf asks the adapter (or its custom adapter) for its SQL dialect.
func dialectOf(a *betterauth.Auth) string {
	if a == nil || a.Context() == nil || a.Context().Adapter == nil {
		return ""
	}
	candidates := []any{a.Context().Adapter}
	if m := reflect.ValueOf(a.Context().Adapter).MethodByName("Custom"); m.IsValid() && m.Type().NumIn() == 0 && m.Type().NumOut() == 1 {
		candidates = append(candidates, m.Call(nil)[0].Interface())
	}
	for _, c := range candidates {
		if c == nil {
			continue
		}
		m := reflect.ValueOf(c).MethodByName("Dialect")
		if !m.IsValid() || m.Type().NumIn() != 0 || m.Type().NumOut() != 1 || m.Type().Out(0).Kind() != reflect.String {
			continue
		}
		if d := m.Call(nil)[0].String(); d != "" {
			return d
		}
	}
	return ""
}

func (r *runner) betterAuthInfo() *object {
	version := moduleVersion()
	if version == "" {
		version = "Unknown"
	}
	o := newObject().set("version", version).set("upstreamVersion", betterauth.Version)
	auth, err := r.loadAuth("info")
	if err != nil {
		o.set("config", nil)
		o.set("error", err.Error())
		return o
	}
	database := newObject().set("adapter", orUnknown(adapterID(auth)))
	d := dialectOf(auth)
	if d == "" && r.opts.Dialect != nil {
		d = r.opts.Dialect()
	}
	if d != "" {
		database.set("dialect", d)
	}
	o.set("database", database)
	o.set("config", sanitizeConfig(auth.Options()))
	return o
}

func (r *runner) info(fs *flag.FlagSet) int {
	// --cwd is accepted for compatibility; upstream reads package.json there, which has no
	// Go counterpart (dependencies come from the binary's build info).
	asJSON := boolean(fs, "json", "j")
	doCopy := boolean(fs, "copy", "c")
	sys := systemInfo()
	goi := goInfo()
	mod := moduleInfo()
	frameworks := buildDeps(reportedFrameworks)
	databases := buildDeps(reportedDatabases)
	ba := r.betterAuthInfo()
	listOrNil := func(l []any) any {
		if len(l) == 0 {
			return nil
		}
		return l
	}
	full := newObject().
		set("system", sys).
		set("go", goi).
		set("module", mod).
		set("frameworks", listOrNil(frameworks)).
		set("databases", listOrNil(databases)).
		set("betterAuth", ba)

	if asJSON {
		js := indentJSON(full)
		fmt.Fprintln(r.stdout, js)
		if doCopy {
			if copyToClipboard(js) {
				fmt.Fprintln(r.stdout, r.st.green("\n✓ Copied to clipboard"))
			} else {
				fmt.Fprintln(r.stdout, r.st.yellow("\n⚠ Could not copy to clipboard"))
			}
		}
		return 0
	}

	w := r.stdout
	fmt.Fprintln(w, r.st.bold("\n📊 Better Auth System Information\n"))
	fmt.Fprintln(w, r.st.gray(strings.Repeat("=", 50)))
	fmt.Fprintln(w, r.st.boldWhite("\n🖥️  System Information:"))
	fmt.Fprintln(w, r.format(sys, 2))
	fmt.Fprintln(w, r.st.boldWhite("\n📦 Go:"))
	fmt.Fprintln(w, r.format(goi, 2))
	fmt.Fprintln(w, r.st.boldWhite("\n📦 Module:"))
	fmt.Fprintln(w, r.format(mod, 2))
	if len(frameworks) > 0 {
		fmt.Fprintln(w, r.st.boldWhite("\n🚀 Frameworks:"))
		fmt.Fprintln(w, r.format(frameworks, 2))
	}
	if len(databases) > 0 {
		fmt.Fprintln(w, r.st.boldWhite("\n💾 Database Clients:"))
		fmt.Fprintln(w, r.format(databases, 2))
	}
	fmt.Fprintln(w, r.st.boldWhite("\n🔐 Better Auth:"))
	v, _ := ba.get("version")
	fmt.Fprintf(w, "  %s: %v\n", r.st.cyan("Version"), v)
	uv, _ := ba.get("upstreamVersion")
	fmt.Fprintf(w, "  %s: %v\n", r.st.cyan("Upstream Version"), uv)
	if e, ok := ba.get("error"); ok {
		fmt.Fprintf(w, "  %s %v\n", r.st.red("Error:"), e)
	} else {
		if d, ok := ba.get("database"); ok {
			fmt.Fprintf(w, "  %s:\n", r.st.cyan("Database"))
			fmt.Fprintln(w, r.format(d, 4))
		}
		if c, ok := ba.get("config"); ok && c != nil {
			if co, isObj := c.(*object); !isObj || co != nil {
				fmt.Fprintf(w, "  %s:\n", r.st.cyan("Configuration"))
				fmt.Fprintln(w, r.format(c, 4))
			}
		}
	}
	fmt.Fprintln(w, r.st.gray("\n"+strings.Repeat("=", 50)))
	fmt.Fprintln(w, r.st.gray("\n💡 Tip: Use --json flag for JSON output"))
	fmt.Fprintln(w, r.st.gray("💡 Use --copy flag to copy output to clipboard"))
	fmt.Fprintln(w, r.st.gray("💡 When reporting issues, include this information\n"))
	if doCopy {
		text := "\nBetter Auth System Information\n==============================\n" +
			"System Information:\n" + indentJSON(sys) + "\n" +
			"Go:\n" + indentJSON(goi) + "\n" +
			"Module:\n" + indentJSON(mod) + "\n" +
			"Frameworks:\n" + indentJSON(listOrNil(frameworks)) + "\n" +
			"Database Clients:\n" + indentJSON(listOrNil(databases)) + "\n" +
			"Better Auth:\n" + indentJSON(ba) + "\n"
		if copyToClipboard(text) {
			fmt.Fprintln(w, r.st.green("✓ Copied to clipboard"))
		} else {
			fmt.Fprintln(w, r.st.yellow("⚠ Could not copy to clipboard"))
		}
	}
	return 0
}

func indentJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "null"
	}
	return string(b)
}

// format is upstream's formatOutput.
func (r *runner) format(data any, indent int) string {
	spaces := strings.Repeat(" ", indent)
	switch x := data.(type) {
	case nil:
		return spaces + r.st.gray("N/A")
	case *object:
		if x == nil {
			return spaces + r.st.gray("N/A")
		}
		if x.len() == 0 {
			return spaces + r.st.gray("{}")
		}
		lines := make([]string, 0, x.len())
		for _, k := range x.keys {
			v := x.vals[k]
			if o, ok := v.(*object); ok && o != nil {
				lines = append(lines, spaces+r.st.cyan(k)+":\n"+r.format(o, indent+2))
				continue
			}
			lines = append(lines, spaces+r.st.cyan(k)+": "+r.format(v, 0))
		}
		return strings.Join(lines, "\n")
	case []any:
		if len(x) == 0 {
			return spaces + r.st.gray("[]")
		}
		lines := make([]string, len(x))
		for i, item := range x {
			lines[i] = r.format(item, indent)
		}
		return strings.Join(lines, "\n")
	}
	return spaces + formatScalar(data)
}

// copyToClipboard pipes s to pbcopy, xclip or clip like upstream.
func copyToClipboard(s string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case "windows":
		cmd = exec.Command("clip")
	default:
		return false
	}
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run() == nil
}
