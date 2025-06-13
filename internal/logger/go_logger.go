package logger

import (
	"log"
	"os"
)

// Wrapper from *log.Logger to logger.Logger interface
// This can be removed when we use the Logger interface everywhere

type GoDebugLogWrapper struct {
	debug *log.Logger
}

func NewGoDebugLogWrapper(debug *log.Logger) *GoDebugLogWrapper {
	g := &GoDebugLogWrapper{
		debug: debug,
	}
	g.debug.SetOutput(os.Stdout)
	return g
}

func (l *GoDebugLogWrapper) Debug(msg string) {
	l.debug.Println(msg)
}

func (l *GoDebugLogWrapper) Info(msg string) {
	l.debug.Println(msg)
}

func (l *GoDebugLogWrapper) Warn(msg string) {
	l.debug.Println(msg)
}
