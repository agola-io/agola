package util

import "testing"

var (
	goodNames = []string{
		"bar",
		"foo-bar",
		"foo-bar-baz",
		"foo1",
		"foo-1",
		"foo-1-bar",
		"f12oo-bar33",
	}
	badNames = []string{
		"",
		"foo bar",
		" foo bar",
		"foo bar ",
		"-bar",
		"bar-",
		"-foo-bar",
		"foo-bar-",
		"foo--bar",
		"foo.bar",
		"foo_bar",
		"foo#bar",
		"1foobar",
	}
)

func TestValidateName(t *testing.T) {
	for _, name := range goodNames {
		ok := ValidateName(name)
		if !ok {
			t.Errorf("expect valid name for %q", name)
		}
	}
	for _, name := range badNames {
		ok := ValidateName(name)
		if ok {
			t.Errorf("expect invalid name for %q", name)
		}
	}
}
