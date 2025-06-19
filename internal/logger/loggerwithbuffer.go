package logger

import (
	"bytes"
	"io"
	"log"
)

type LogWithBuffer struct {
	buf   *bytes.Buffer
	debug *log.Logger
	info  *log.Logger
	warn  *log.Logger
}

func NewLogWithBuffer(logLevel string, buf *bytes.Buffer) *LogWithBuffer {
	infoHandle := log.New(io.Discard, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	debugHandle := log.New(io.Discard, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	warnHandle := log.New(io.Discard, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile)

	s := &LogWithBuffer{
		buf:   buf,
		debug: debugHandle,
		info:  infoHandle,
		warn:  warnHandle,
	}

	s.warn.SetOutput(buf)

	switch logLevel {
	case "INFO":
		s.info.SetOutput(buf)
	case "DEBUG":
		s.info.SetOutput(buf)
		s.debug.SetOutput(buf)
	}

	return s
}

func (l *LogWithBuffer) Debug(msg string) {
	l.debug.Println(msg)
}

func (l *LogWithBuffer) Info(msg string) {
	l.info.Println(msg)
}

func (l *LogWithBuffer) Warn(msg string) {
	l.warn.Println(msg)
}
