package logger

import (
	"io"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStdLog(t *testing.T) {
	t.Run("expect panic if handles are nil", func(t *testing.T) {
		assert.Panics(t, func() {
			NewStdLog(nil, nil, nil, "warn")
		})
	})
	t.Run("expect initialisation", func(t *testing.T) {
		assert.NotPanics(t, func() {
			NewStdLog(
				log.New(io.Discard, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile),
				log.New(io.Discard, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
				log.New(io.Discard, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile),
				"warn")
		})
	})
}
