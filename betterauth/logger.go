package betterauth

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Logger receives Better Auth logs. Implementations must be safe for concurrent use.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// LogLevel names, ordered by verbosity.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

type slogLogger struct {
	l     *slog.Logger
	level slog.Level
}

// NewLogger returns a slog-based Logger writing to stderr at the given level
// ("debug", "info", "warn", "error"). A nil handler uses a text handler.
func NewLogger(level string, h slog.Handler) Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case LevelDebug:
		lv = slog.LevelDebug
	case LevelInfo:
		lv = slog.LevelInfo
	case LevelError:
		lv = slog.LevelError
	default:
		lv = slog.LevelWarn
	}
	if h == nil {
		h = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})
	}
	return &slogLogger{l: slog.New(h).With("component", "better-auth"), level: lv}
}

func (s *slogLogger) log(lv slog.Level, msg string, args ...any) {
	if !s.l.Enabled(context.Background(), lv) {
		return
	}
	attrs := make([]any, 0, len(args))
	for i, a := range args {
		attrs = append(attrs, slog.Any(fmt.Sprintf("arg%d", i), a))
	}
	s.l.Log(context.Background(), lv, msg, attrs...)
}

func (s *slogLogger) Debug(msg string, args ...any) { s.log(slog.LevelDebug, msg, args...) }
func (s *slogLogger) Info(msg string, args ...any)  { s.log(slog.LevelInfo, msg, args...) }
func (s *slogLogger) Warn(msg string, args ...any)  { s.log(slog.LevelWarn, msg, args...) }
func (s *slogLogger) Error(msg string, args ...any) { s.log(slog.LevelError, msg, args...) }

// NopLogger discards all logs.
type NopLogger struct{}

func (NopLogger) Debug(string, ...any) {}
func (NopLogger) Info(string, ...any)  {}
func (NopLogger) Warn(string, ...any)  {}
func (NopLogger) Error(string, ...any) {}
