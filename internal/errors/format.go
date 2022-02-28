package errors

import (
	"errors"
	"fmt"
)

func PrintErrorDetails(err error) []string {
	type stackTracer interface {
		StackTrace() StackTrace
	}
	type errWithStack struct {
		err   error
		msg   string
		stack StackTrace
	}

	var stackErrs []errWithStack
	errCause := err
	for errCause != nil {
		stackErr := errWithStack{
			err: errCause,
			msg: errCause.Error(),
		}
		//nolint:errorlint
		if s, ok := errCause.(stackTracer); ok {
			stackErr.stack = s.StackTrace()
		}
		stackErrs = append(stackErrs, stackErr)
		errCause = errors.Unwrap(errCause)
		if err == nil {
			break
		}
	}

	var lines []string
	for _, stackErr := range stackErrs {
		if len(stackErr.stack) > 0 {
			frame := stackErr.stack[0]
			lines = append(lines, fmt.Sprintf("(%T) %+v: %s", stackErr.err, frame, stackErr.msg))
		} else {
			lines = append(lines, fmt.Sprintf("(%T) %s", stackErr.err, stackErr.msg))
		}
	}

	return lines
}
