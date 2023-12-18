package testutil

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
)

func NewLogger(t *testing.T) zerolog.Logger {
	detailedErrors, _ := strconv.ParseBool(os.Getenv("DETAILED_ERRORS"))

	if detailedErrors {
		zerolog.ErrorMarshalFunc = errors.ErrorMarshalFunc
	}

	cw := zerolog.ConsoleWriter{
		Out:                 zerolog.TestWriter{T: t, Frame: 6},
		TimeFormat:          time.RFC3339Nano,
		FormatErrFieldValue: errors.FormatErrFieldValue,
	}

	zerolog.TimeFieldFormat = time.RFC3339Nano

	return zerolog.New(cw).With().Timestamp().Stack().Caller().Logger().Level(zerolog.InfoLevel).Output(cw)
}

type helperT interface {
	Helper()
}
