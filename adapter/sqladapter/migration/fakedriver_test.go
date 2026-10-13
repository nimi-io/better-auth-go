package migration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"testing"
)

// emptyDriver is a database/sql driver whose queries return no rows and whose statements
// fail. It stands in for SQL Server, which has no test database: the planner introspects an
// empty database and the fixtures check the compiled DDL (as the TypeScript generator does
// with a fake Kysely driver).
type emptyDriver struct{}

func (emptyDriver) Open(string) (driver.Conn, error) { return emptyConn{}, nil }

type emptyConn struct{}

func (emptyConn) Prepare(string) (driver.Stmt, error) { return emptyStmt{}, nil }
func (emptyConn) Close() error                        { return nil }
func (emptyConn) Begin() (driver.Tx, error)           { return nil, errors.New("emptyDriver: no transactions") }

func (emptyConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return emptyRows{}, nil
}

type emptyStmt struct{}

func (emptyStmt) Close() error  { return nil }
func (emptyStmt) NumInput() int { return -1 }
func (emptyStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("emptyDriver: statements are not executed")
}
func (emptyStmt) Query([]driver.Value) (driver.Rows, error) { return emptyRows{}, nil }

type emptyRows struct{}

func (emptyRows) Columns() []string         { return nil }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

var registerEmpty sync.Once

func emptyDB(t *testing.T) *sql.DB {
	t.Helper()
	registerEmpty.Do(func() { sql.Register("ba-migration-empty", emptyDriver{}) })
	conn, err := sql.Open("ba-migration-empty", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}
