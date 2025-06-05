package logger

import (
	"log"
	"os"
)

type Logger interface {
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
}

type StdLog struct {
	debug *log.Logger
	info  *log.Logger
	warn  *log.Logger
}

func NewStdLog(debugHandle, infoHandle, warnHandle *log.Logger, logLevel string) *StdLog {
	s := &StdLog{
		debug: debugHandle,
		info:  infoHandle,
		warn:  warnHandle,
	}

	s.warn.SetOutput(os.Stdout)

	switch logLevel {
	case "INFO":
		s.info.SetOutput(os.Stdout)
	case "DEBUG":
		s.info.SetOutput(os.Stdout)
		s.debug.SetOutput(os.Stdout)
	}

	return s
}

func (l *StdLog) Debug(msg string) {
	l.debug.Println(msg)
}

func (l *StdLog) Info(msg string) {
	l.info.Println(msg)
}

func (l *StdLog) Warn(msg string) {
	l.warn.Println(msg)
}
