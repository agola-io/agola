package testutil

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sorintlab/errors"
	"gotest.tools/assert"
)

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
