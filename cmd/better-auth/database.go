package main

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
)

// target is a parsed database location.
type target struct {
	dialect sqladapter.Dialect
	driver  string        // database/sql driver name ("pgx", "sqlite")
	dsn     string        // driver DSN (pgx, sqlite)
	mysql   *mysql.Config // MySQL connections use a connector (no DSN round trip)
}

func (t target) open() (*sql.DB, error) {
	if t.mysql != nil {
		c, err := mysql.NewConnector(t.mysql)
		if err != nil {
			return nil, err
		}
		return sql.OpenDB(c), nil
	}
	return sql.Open(t.driver, t.dsn)
}

func parseDialect(name string) (sqladapter.Dialect, error) {
	switch strings.ToLower(name) {
	case "":
		return "", nil
	case "postgres", "postgresql", "pg", "pgx":
		return sqladapter.Postgres, nil
	case "mysql", "mariadb":
		return sqladapter.MySQL, nil
	case "sqlite", "sqlite3":
		return sqladapter.SQLite, nil
	}
	return "", fmt.Errorf("unsupported dialect %q (expected postgres, mysql or sqlite)", name)
}

// parseDatabaseURL resolves a --database-url value; override is the --dialect flag.
func parseDatabaseURL(raw, override string) (target, error) {
	want, err := parseDialect(override)
	if err != nil {
		return target{}, err
	}
	scheme, rest, hasScheme := strings.Cut(raw, ":")
	scheme = strings.ToLower(scheme)
	var t target
	switch {
	case hasScheme && (scheme == "postgres" || scheme == "postgresql") && strings.HasPrefix(rest, "//"):
		t = target{dialect: sqladapter.Postgres, driver: "pgx", dsn: raw}
	case hasScheme && (scheme == "mysql" || scheme == "mariadb") && strings.HasPrefix(rest, "//"):
		cfg, err := mysqlURL(raw)
		if err != nil {
			return target{}, err
		}
		t = target{dialect: sqladapter.MySQL, mysql: cfg}
	case hasScheme && (scheme == "sqlite" || scheme == "sqlite3"):
		path := rest
		if strings.HasPrefix(path, "//") {
			path = path[2:] // sqlite://rel.db, sqlite:///abs/path.db
		}
		t = target{dialect: sqladapter.SQLite, driver: "sqlite", dsn: sqliteDSN(path)}
	case hasScheme && scheme == "file":
		t = target{dialect: sqladapter.SQLite, driver: "sqlite", dsn: sqliteDSN(raw)}
	case isSQLitePath(raw):
		t = target{dialect: sqladapter.SQLite, driver: "sqlite", dsn: sqliteDSN(raw)}
	default:
		if want == "" {
			return target{}, errors.New("cannot detect the database from the database URL; use a postgres://, mysql:// or sqlite: URL, or pass --dialect")
		}
		// a driver-native DSN for the requested dialect
		switch want {
		case sqladapter.Postgres:
			return target{dialect: want, driver: "pgx", dsn: raw}, nil
		case sqladapter.MySQL:
			cfg, err := mysql.ParseDSN(raw)
			if err != nil {
				return target{}, fmt.Errorf("invalid MySQL DSN: %w", err)
			}
			cfg.ParseTime = true
			return target{dialect: want, mysql: cfg}, nil
		default:
			return target{dialect: want, driver: "sqlite", dsn: sqliteDSN(raw)}, nil
		}
	}
	if want != "" && want != t.dialect {
		return target{}, fmt.Errorf("--dialect %s does not match the %s database URL", override, t.dialect)
	}
	return t, nil
}

func isSQLitePath(p string) bool {
	l := strings.ToLower(p)
	return l == ":memory:" || strings.HasSuffix(l, ".db") || strings.HasSuffix(l, ".sqlite") || strings.HasSuffix(l, ".sqlite3")
}

// sqliteDSN builds a modernc.org/sqlite DSN with foreign keys on (better-sqlite3's default)
// and a busy timeout.
func sqliteDSN(path string) string {
	dsn := path
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	pragmas := []string{}
	if !strings.Contains(dsn, "foreign_keys") {
		pragmas = append(pragmas, "_pragma=foreign_keys(1)")
	}
	if !strings.Contains(dsn, "busy_timeout") {
		pragmas = append(pragmas, "_pragma=busy_timeout(5000)")
	}
	if len(pragmas) == 0 {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + strings.Join(pragmas, "&")
}

// mysqlURL converts mysql://user:pass@host:port/db?param=value to a go-sql-driver config.
// Query parameters are go-sql-driver DSN parameters; parseTime defaults to true.
func mysqlURL(raw string) (*mysql.Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid MySQL URL: %w", err)
	}
	params := "/"
	if u.RawQuery != "" {
		params += "?" + u.RawQuery
	}
	cfg, err := mysql.ParseDSN(params)
	if err != nil {
		return nil, fmt.Errorf("invalid MySQL URL parameters: %w", err)
	}
	if u.User != nil {
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
	}
	cfg.Net = "tcp"
	host := u.Host
	if host == "" {
		host = "localhost"
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "3306")
	}
	cfg.Addr = host
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	if !u.Query().Has("parseTime") {
		cfg.ParseTime = true
	}
	return cfg, nil
}

// loadDotEnv loads KEY=VALUE lines from path into the environment without overriding
// variables that are already set (dotenv/config upstream).
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'' || value[0] == '`') && value[len(value)-1] == value[0] {
			quote := value[0]
			value = value[1 : len(value)-1]
			if quote == '"' {
				value = strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\"`, `"`).Replace(value)
			}
		} else if i := strings.Index(value, " #"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}
