package testutil

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
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

func NilError(t assert.TestingT, err error, msgAndArgs ...interface{}) {
	if ht, ok := t.(helperT); ok {
		ht.Helper()
	}

	detailedErrors, _ := strconv.ParseBool(os.Getenv("DETAILED_ERRORS"))

	if !assert.Check(t, err, msgAndArgs...) {
		if detailedErrors {
			var sb strings.Builder
			errDetails := errors.PrintErrorDetails(err)
			if len(errDetails) > 0 {
				sb.WriteString("error details:\n")
				for _, l := range errDetails {
					sb.WriteString(fmt.Sprintf("%s\n", l))
				}
			}
			t.Log(sb.String())
		}

		t.FailNow()
	}
}
