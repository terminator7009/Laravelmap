package debug

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
)

// LogLevel represents the verbosity level for debugging
type LogLevel int

const (
	// LevelNone disables all debug output
	LevelNone LogLevel = iota
	// LevelError only shows error messages
	LevelError
	// LevelWarning shows errors and warnings
	LevelWarning
	// LevelInfo shows errors, warnings, and info messages
	LevelInfo
	// LevelDebug shows all messages including detailed debug info
	LevelDebug
	// LevelTrace shows all messages including very detailed trace info
	LevelTrace
)

// Logger handles debug output with different verbosity levels
type Logger struct {
	level      LogLevel
	output     io.Writer
	fileOutput io.Writer
	mu         sync.Mutex
	colors     bool
}

var (
	// Global logger instance
	globalLogger *Logger
	once         sync.Once
)

// GetLogger returns the singleton logger instance
func GetLogger() *Logger {
	once.Do(func() {
		globalLogger = &Logger{
			level:  LevelInfo, // Default level
			output: os.Stdout,
			colors: true,
		}
	})
	return globalLogger
}

// SetLogLevel changes the current logging level
func (l *Logger) SetLogLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput changes where logs are written
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// EnableFileOutput enables logging to a file in addition to the standard output
func (l *Logger) EnableFileOutput(filename string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileOutput = file
	return nil
}

// DisableFileOutput stops logging to file
func (l *Logger) DisableFileOutput() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fileOutput != nil {
		if closer, ok := l.fileOutput.(io.Closer); ok {
			closer.Close()
		}
		l.fileOutput = nil
	}
}

// DisableColors turns off colored output
func (l *Logger) DisableColors() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.colors = false
}

// EnableColors turns on colored output
func (l *Logger) EnableColors() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.colors = true
}

// log writes a message with the given color if the current level is sufficient
func (l *Logger) log(level LogLevel, colorFunc func(format string, a ...interface{}) string, format string, args ...interface{}) {
	if level <= l.level {
		l.mu.Lock()
		defer l.mu.Unlock()

		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		levelStr := getLevelString(level)

		message := fmt.Sprintf(format, args...)
		fullMessage := fmt.Sprintf("[%s] [%s] %s\n", timestamp, levelStr, message)

		// Write to standard output with colors if enabled
		if l.output != nil {
			if l.colors && colorFunc != nil {
				fmt.Fprint(l.output, colorFunc(fullMessage))
			} else {
				fmt.Fprint(l.output, fullMessage)
			}
		}

		// Write to file output without colors
		if l.fileOutput != nil {
			fmt.Fprint(l.fileOutput, fullMessage)
		}
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, color.New(color.FgRed).SprintfFunc(), format, args...)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(LevelWarning, color.New(color.FgYellow).SprintfFunc(), format, args...)
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, color.New(color.FgCyan).SprintfFunc(), format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, color.New(color.FgGreen).SprintfFunc(), format, args...)
}

// Trace logs a trace message (very detailed)
func (l *Logger) Trace(format string, args ...interface{}) {
	l.log(LevelTrace, color.New(color.FgMagenta).SprintfFunc(), format, args...)
}

// HTTPRequest logs HTTP request details
func (l *Logger) HTTPRequest(method, url string, headers map[string]string) {
	if l.level >= LevelDebug {
		l.Debug("HTTP Request: %s %s", method, url)
		for k, v := range headers {
			l.Trace("  Header: %s: %s", k, v)
		}
	}
}

// HTTPResponse logs HTTP response details
func (l *Logger) HTTPResponse(statusCode int, url string, headers map[string][]string, bodySize int) {
	if l.level >= LevelDebug {
		l.Debug("HTTP Response: %d from %s (body size: %d bytes)", statusCode, url, bodySize)
		if l.level >= LevelTrace {
			for k, v := range headers {
				l.Trace("  Header: %s: %v", k, v)
			}
		}
	}
}

// ScanStart logs the start of a scan
func (l *Logger) ScanStart(scanName, target string) {
	l.Info("Starting scan: %s on target %s", scanName, target)
}

// ScanEnd logs the end of a scan
func (l *Logger) ScanEnd(scanName string, resultsCount int, duration time.Duration) {
	l.Info("Completed scan: %s with %d results in %v", scanName, resultsCount, duration)
}

// getLevelString returns a string representation of the log level
func getLevelString(level LogLevel) string {
	switch level {
	case LevelError:
		return "ERROR"
	case LevelWarning:
		return "WARN "
	case LevelInfo:
		return "INFO "
	case LevelDebug:
		return "DEBUG"
	case LevelTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}
