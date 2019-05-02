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
		"cba7b810-9dad-11d1-80b4-00c04fd430c",
		"cba7b810-9dad-11d1-80b4000c04fd430c8",
		"cba7b8109dad11d180b400c04fd430c89",
		"cba7b8109dad11d180b400c04fd430c",
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
		"cba7b810-9dad-11d1-80b4-00c04fd430c8",
		"{cba7b810-9dad-11d1-80b4-00c04fd430c8}",
		"urn:uuid:cba7b810-9dad-11d1-80b4-00c04fd430c8",
		"cba7b8109dad11d180b400c04fd430c8",
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
