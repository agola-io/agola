package main

import (
	"flag"

	"github.com/sorintlab/errors"

	csobjects "agola.io/agola/internal/services/configstore/db/objects"
	rsobjects "agola.io/agola/internal/services/runservice/db/objects"
	"agola.io/agola/internal/sqlg/gen"
)

var genType string
var componentName string

func init() {
	flag.StringVar(&genType, "type", "", "generator type")
	flag.StringVar(&componentName, "component", "", "component name")
}

func main() {
	flag.Parse()

	switch genType {
	case "db":
		switch componentName {
		case "runservice":
			gen.GenDB(rsobjects.Version, rsobjects.ObjectsInfo, rsobjects.TypesImport, rsobjects.AdditionalImports)
		case "configstore":
			gen.GenDB(csobjects.Version, csobjects.ObjectsInfo, csobjects.TypesImport, csobjects.AdditionalImports)
		default:
			panic(errors.Errorf("wrong component name %q", componentName))
		}
	case "dbfixtures":
		switch componentName {
		case "runservice":
			gen.GenDBFixtures(rsobjects.Version, rsobjects.ObjectsInfo, rsobjects.TypesImport, rsobjects.AdditionalImports)
		case "configstore":
			gen.GenDBFixtures(csobjects.Version, csobjects.ObjectsInfo, csobjects.TypesImport, csobjects.AdditionalImports)
		default:
			panic(errors.Errorf("wrong component name %q", componentName))
		}
	default:
		panic(errors.Errorf("wrong generator type %q", genType))
	}
}
