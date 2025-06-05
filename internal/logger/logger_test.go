package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStdLog(t *testing.T) {
	t.Run("expect initialisation", func(t *testing.T) {
		assert.NotPanics(t, func() {
			NewStdLog("warn")
		})
	})
}
