package gen

import (
	"text/template"

	"github.com/iancoleman/strcase"

	"agola.io/agola/internal/sqlg"
)

type genData struct {
	Version           uint
	ObjectsInfo       []sqlg.ObjectInfo
	TypesImport       string
	AdditionalImports []string
	HasJSON           bool
}

var funcs = template.FuncMap{
	"lowerCamel": strcase.ToLowerCamel,
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
