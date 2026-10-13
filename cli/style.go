package cli

import (
	"io"
	"os"
	"path/filepath"
)

// styles applies ANSI colors like chalk; every method is the identity when color is off.
type styles struct{ on bool }

func newStyles(on bool) styles { return styles{on: on} }

func (s styles) wrap(code, v string) string {
	if !s.on {
		return v
	}
	return "\x1b[" + code + "m" + v + "\x1b[0m"
}

func (s styles) bold(v string) string    { return s.wrap("1", v) }
func (s styles) red(v string) string     { return s.wrap("31", v) }
func (s styles) redBold(v string) string { return s.wrap("1;31", v) }
func (s styles) green(v string) string   { return s.wrap("32", v) }
func (s styles) yellow(v string) string  { return s.wrap("33", v) }
func (s styles) magenta(v string) string { return s.wrap("35", v) }
func (s styles) cyan(v string) string    { return s.wrap("36", v) }
func (s styles) white(v string) string   { return s.wrap("37", v) }
func (s styles) boldWhite(v string) string {
	return s.wrap("1;37", v)
}
func (s styles) gray(v string) string { return s.wrap("90", v) }

// useColor mirrors chalk's detection: FORCE_COLOR / NO_COLOR, then whether w is a terminal.
func useColor(force *bool, w io.Writer) bool {
	if force != nil {
		return *force
	}
	if v, ok := os.LookupEnv("FORCE_COLOR"); ok {
		return v != "0" && v != "false"
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func absPath(p string) (string, error) {
	if p == "" {
		return os.Getwd()
	}
	return filepath.Abs(p)
}
