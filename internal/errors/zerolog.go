package errors

import (
	"encoding/json"
	"fmt"
	"strings"
)

// copied from zerolog console writer since they aren't exported
//nolint
const (
	colorBlack = iota + 30
	colorRed
	colorGreen
	colorYellow
	colorBlue
	colorMagenta
	colorCyan
	colorWhite
)

// colorize returns the string s wrapped in ANSI code c, unless disabled is true.
func colorize(s interface{}, c int, disabled bool) string {
	if disabled {
		return fmt.Sprintf("%s", s)
	}
	return fmt.Sprintf("\x1b[%dm%v\x1b[0m", c, s)
}

type errorFormat = struct {
	Error   string
	Details []string
}

func FormatErrFieldValue(i interface{}) string {
	switch d := i.(type) {
	case []byte:
		var ed errorFormat
		if err := json.Unmarshal(d, &ed); err != nil {
			return fmt.Sprintf("error: %v", err)
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%s\n", ed.Error))
		if len(ed.Details) > 0 {
			sb.WriteString("error details:\n")
			for _, l := range ed.Details {
				sb.WriteString(fmt.Sprintf("%s\n", l))
			}
		}
		return colorize(sb.String(), colorRed, false)

	default:
		return colorize(fmt.Sprintf("%s", d), colorRed, false)
	}
}

func ErrorMarshalFunc(err error) interface{} {
	ef := errorFormat{
		Error:   err.Error(),
		Details: PrintErrorDetails(err),
	}
	return ef
}
