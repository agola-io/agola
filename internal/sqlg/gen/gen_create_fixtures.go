package gen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"agola.io/agola/internal/sqlg/sql"
)

type CreateFixtureData struct {
	DDL       map[string][]string      `json:"ddl"`
	Sequences []CreateFixtureSequence  `json:"sequences"`
	Tables    []CreateFixtureTableInfo `json:"tables"`
}

type CreateFixtureDDL struct {
	Postgres []string `json:"postgres"`
	Sqlite3  []string `json:"sqlite3"`
}

type CreateFixtureTableInfo struct {
	Name    string                 `json:"name"`
	Columns []CreateFixtureColInfo `json:"columns"`
}

type CreateFixtureColInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

type CreateFixtureSequence struct {
	Name   string `json:"name"`
	Table  string `json:"table"`
	Column string `json:"column"`
}

func genCreateFixtures(gd *genData) {
	data := genDDLGenericData(gd)
	for _, dbType := range []sql.Type{sql.Postgres, sql.Sqlite3} {
		data.Data[dbType] = genDDLData(gd, dbType)
	}

	fd := CreateFixtureData{
		DDL:       make(map[string][]string),
		Sequences: []CreateFixtureSequence{},
	}
	for _, dbType := range []sql.Type{sql.Postgres, sql.Sqlite3} {
		ddls := []string{}
		for _, tableDef := range data.Data[dbType].TableDefs {
			ddls = append(ddls, tableDef.DDL)
		}

		ddls = append(ddls, data.Data[dbType].IndexDefs...)

		fd.DDL[string(dbType)] = ddls

	}

	for _, seq := range data.Sequences {
		fd.Sequences = append(fd.Sequences, CreateFixtureSequence{
			Name:   seq.Name,
			Table:  seq.TableName,
			Column: seq.ColName,
		})
	}

	for _, tableInfo := range data.Tables {
		ti := CreateFixtureTableInfo{
			Name:    tableInfo.Name,
			Columns: []CreateFixtureColInfo{},
		}
		for _, colInfo := range tableInfo.Columns {
			ci := CreateFixtureColInfo{
				Name:     colInfo.Name,
				Type:     colInfo.Type,
				Nullable: colInfo.Nullable,
			}
			if colInfo.JSON {
				ci.Type = "json"
			}

			ti.Columns = append(ti.Columns, ci)
		}

		fd.Tables = append(fd.Tables, ti)
	}

	f, err := os.Create(filepath.Join("fixtures", "create", fmt.Sprintf("v%d.json", gd.Version)))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "\t")
	if err := e.Encode(fd); err != nil {
		panic(err)
	}
}
