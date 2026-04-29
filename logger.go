package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

// Logger provides structured, leveled logging for the scan pipeline.
// It replaces the bare `debugLogger` function type with a proper
// logging facility that supports levels, output redirection, and
// thread-safe writes.
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	minLevel LogLevel
	prefix   string
	entries  []LogEntry
}

// LogEntry represents a single log message for post-scan analysis.
type LogEntry struct {
	Timestamp string   `json:"timestamp"`
	Level     string   `json:"level"`
	Message   string   `json:"message"`
}

// NewLogger creates a logger that writes to the given writer at the
// specified minimum level.
func NewLogger(out io.Writer, minLevel LogLevel) *Logger {
	return &Logger{out: out, minLevel: minLevel}
}

// WithPrefix returns a new logger with the given prefix.
// The child logger has its own entry list and does not share
// the parent's entries slice.
func (l *Logger) WithPrefix(prefix string) *Logger {
	return &Logger{
		out:      l.out,
		minLevel: l.minLevel,
		prefix:   prefix,
	}
}

// Debug logs a message at DEBUG level.
func (l *Logger) Debug(format string, args ...any) {
	l.log(LogDebug, format, args...)
}

// Info logs a message at INFO level.
func (l *Logger) Info(format string, args ...any) {
	l.log(LogInfo, format, args...)
}

// Warn logs a message at WARN level.
func (l *Logger) Warn(format string, args ...any) {
	l.log(LogWarn, format, args...)
}

// Error logs a message at ERROR level.
func (l *Logger) Error(format string, args ...any) {
	l.log(LogError, format, args...)
}

// Debugf is an alias for Debug that satisfies the debugLogger type.
func (l *Logger) Debugf(format string, args ...any) {
	l.log(LogDebug, format, args...)
}

// AsDebugLogger returns a debugLogger function that delegates to this
// logger, allowing backward-compatible usage with existing code.
func (l *Logger) AsDebugLogger() debugLogger {
	return func(format string, args ...any) {
		l.log(LogDebug, format, args...)
	}
}

// Entries returns all captured log entries.
func (l *Logger) Entries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Strings returns all log messages as strings (for DebugLog field).
func (l *Logger) Strings() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.entries))
	for i, e := range l.entries {
		out[i] = fmt.Sprintf("[%s] %s", e.Level, e.Message)
	}
	return out
}

func (l *Logger) log(level LogLevel, format string, args ...any) {
	if level < l.minLevel {
		return
	}

	msg := fmt.Sprintf(format, args...)
	if l.prefix != "" {
		msg = l.prefix + ": " + msg
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     levelName(level),
		Message:   msg,
	}

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	if l.out != nil {
		fmt.Fprintf(l.out, "[%s] %s\n", entry.Level, msg)
	}
	l.mu.Unlock()
}

func levelName(level LogLevel) string {
	switch level {
	case LogDebug:
		return "DEBUG"
	case LogInfo:
		return "INFO"
	case LogWarn:
		return "WARN"
	case LogError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// NewScanLogger creates a logger configured for scan pipeline use.
// In debug mode, writes to stderr; otherwise captures entries silently.
func NewScanLogger(debug bool) *Logger {
	if debug {
		return NewLogger(os.Stderr, LogDebug)
	}
	return NewLogger(nil, LogDebug)
}
