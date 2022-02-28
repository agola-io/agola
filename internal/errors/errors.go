package errors

import (
	"fmt"
	"io"
)

type werror struct {
	cause error
	msg   string
	*Stack
}

func (w *werror) Error() string {
	if w.cause == nil {
		return w.msg
	}
	if w.msg != "" {
		return w.msg + ": " + w.cause.Error()
	} else {
		return w.cause.Error()
	}
}

func (w *werror) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, w.Error())
}

func (w *werror) Unwrap() error { return w.cause }

// New returns an error with the supplied message.
// New also records the stack trace at the point it was called.
func New(message string) error {
	return &werror{
		msg:   message,
		Stack: Callers(0),
	}
}

// Errorf formats according to a format specifier and returns the string
// as a value that satisfies error.
// Errorf also records the stack trace at the point it was called.
func Errorf(format string, args ...interface{}) error {
	return &werror{
		msg:   fmt.Sprintf(format, args...),
		Stack: Callers(0),
	}
}

// WithStack annotates err with a stack trace at the point WithStack was called.
// If err is nil, WithStack returns nil.
func WithStack(err error) error {
	if err == nil {
		return nil
	}
	return &werror{
		err,
		"",
		Callers(0),
	}
}

// Wrap returns an error annotating err with a stack trace
// at the point Wrap is called, and the supplied message.
// If err is nil, Wrap returns nil.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return &werror{
		err,
		message,
		Callers(0),
	}
}

// Wrapf returns an error annotating err with a stack trace
// at the point Wrapf is called, and the format specifier.
// If err is nil, Wrapf returns nil.
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	return &werror{
		err,
		fmt.Sprintf(format, args...),
		Callers(0),
	}
}
