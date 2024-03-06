package gen

import (
	"strings"
	"text/template"

	"agola.io/agola/internal/sqlg"
)

type genData struct {
	Version           uint
	ObjectsInfo       []sqlg.ObjectInfo
	TypesImport       string
	AdditionalImports []string
	HasJSON           bool
}

// Converts a string to CamelCase
// taken from github.com/iancoleman/strcase v0.2.0 since v0.3.0 changed the behavior.
func toCamelInitCase(s string, initCase bool) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	n := strings.Builder{}
	n.Grow(len(s))
	capNext := initCase
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if capNext {
			if vIsLow {
				v += 'A'
				v -= 'a'
			}
		} else if i == 0 {
			if vIsCap {
				v += 'a'
				v -= 'A'
			}
		}
		if vIsCap || vIsLow {
			n.WriteByte(v)
			capNext = false
		} else if vIsNum := v >= '0' && v <= '9'; vIsNum {
			n.WriteByte(v)
			capNext = true
		} else {
			capNext = v == '_' || v == ' ' || v == '-' || v == '.'
		}
	}
	return n.String()
}

// ToCamel converts a string to CamelCase
func ToCamel(s string) string {
	return toCamelInitCase(s, true)
}

// ToLowerCamel converts a string to lowerCamelCase
func ToLowerCamel(s string) string {
	return toCamelInitCase(s, false)
}

var funcs = template.FuncMap{
	"lowerCamel": ToLowerCamel,
	`tick`:       func() string { return "`" },
}

func objectMetaFields() []sqlg.ObjectField {
	return []sqlg.ObjectField{
		{Name: "ID", Type: "string"},
		{Name: "Revision", Type: "uint64"},
		{Name: "CreationTime", Type: "time.Time"},
		{Name: "UpdateTime", Type: "time.Time"},
	}
}

func GenDB(version uint, objectsInfo []sqlg.ObjectInfo, typesImport string, additionalImports []string) {
	hasJSON := false
	for _, oi := range objectsInfo {
		for _, of := range oi.Fields {
			if of.JSON {
				hasJSON = true
				break
			}
		}
	}

	gd := &genData{
		Version:           version,
		ObjectsInfo:       objectsInfo,
		TypesImport:       typesImport,
		AdditionalImports: additionalImports,
		HasJSON:           hasJSON,
	}

	genMethods(gd)
	genDDL(gd)
	genDML(gd)
	genFetch(gd)
}

func GenDBFixtures(version uint, objectsInfo []sqlg.ObjectInfo, typesImport string, additionalImports []string) {
	hasJSON := false
	for _, oi := range objectsInfo {
		for _, of := range oi.Fields {
			if of.JSON {
				hasJSON = true
				break
			}
		}
	}

	gd := &genData{
		Version:           version,
		ObjectsInfo:       objectsInfo,
		TypesImport:       typesImport,
		AdditionalImports: additionalImports,
		HasJSON:           hasJSON,
	}

	genCreateFixtures(gd)
}
