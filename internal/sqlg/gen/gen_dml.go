package gen

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"

	"github.com/Masterminds/sprig/v3"
	"github.com/huandu/xstrings"
	"github.com/iancoleman/strcase"
)

type DMLGenericData struct {
	TableDefs         []DMLGenericDataTable
	TypesImport       string
	AdditionalImports []string
	HasJSON           bool
	HasSequences      bool
}

type DMLGenericDataTable struct {
	Table                string
	ObjectName           string
	LowerObjectName      string
	LowerCamelObjectName string
	SelectColumns        []string
	ScanFields           []string
	MapFields            []DMLDataTableMapField
	FuncPrefix           string
	JSONValues           []DMLDataTableJSON
	Sequences            []DMLDataTableSequence
}

type DMLData struct {
	DBType            string
	TableDefs         []DMLDataTable
	RawInsertSuffix   string
	TypesImport       string
	AdditionalImports []string
	HasJSON           bool
}

type DMLDataTable struct {
	Table                string
	LowerTable           string
	ObjectName           string
	LowerObjectName      string
	LowerCamelObjectName string
	InsertColumns        []string
	FuncPrefix           string
	InsertFuncParams     []string
	UpdateFuncParams     []string
	InsertVarNames       []string
	UpdateVarNames       []string
	InsertValues         []string
	UpdateSets           []string
	RawFuncParams        []string
	RawInsertColumns     []string
	RawInsertValues      []string
	RawInsertVarNames    []string
	JSONValues           []DMLDataTableJSON
}

type DMLDataTableSequence struct {
	Name    string
	ColName string
	Field   string
}

type DMLDataTableMapField struct {
	ColName   string
	Field     string
	FieldType string
	JSON      bool
}

type DMLDataTableJSON struct {
	VarName   string
	Field     string
	FullField string
}

func genDMLGenericData(gd *genData) DMLGenericData {
	objectsInfo := []sqlg.ObjectInfo{}
	for _, oi := range gd.ObjectsInfo {
		oi.Fields = append(objectMetaFields(), oi.Fields...)

		objectsInfo = append(objectsInfo, oi)
	}

	objectsInfo = sqlg.PopulateObjectsInfo(objectsInfo, "")

	data := DMLGenericData{TypesImport: gd.TypesImport, AdditionalImports: gd.AdditionalImports, HasJSON: gd.HasJSON}

	for _, oi := range objectsInfo {
		tableDef := DMLGenericDataTable{Table: oi.Table, ObjectName: oi.Name}
		tableDef.LowerObjectName = strings.ToLower(oi.Name)
		tableDef.LowerCamelObjectName = strcase.ToLowerCamel(oi.Name)
		tableDef.FuncPrefix = strcase.ToLowerCamel(oi.Name)

		for _, of := range oi.Fields {
			colName := of.ColName
			fullColName := fmt.Sprintf("\"%s.%s\"", oi.Table, colName)
			fullField := fmt.Sprintf("%s.%s", tableDef.LowerObjectName, of.Name)

			fieldType := of.Type
			if of.Nullable {
				fieldType = "*" + fieldType
			}

			paramName := "in" + strcase.ToCamel(of.Name)

			var scanField string
			if of.JSON {
				scanField = fmt.Sprintf("&%sJSON", paramName)
			} else {
				scanField = fmt.Sprintf("&v.%s", of.Name)
			}

			mapField := fmt.Sprintf("v.%s", of.Name)

			tableDef.SelectColumns = append(tableDef.SelectColumns, fullColName)
			tableDef.ScanFields = append(tableDef.ScanFields, scanField)
			tableDef.MapFields = append(tableDef.MapFields, DMLDataTableMapField{
				ColName:   fullColName,
				Field:     mapField,
				FieldType: fieldType,
				JSON:      of.JSON,
			})

			if of.JSON {
				tableDef.JSONValues = append(tableDef.JSONValues, DMLDataTableJSON{
					VarName:   paramName,
					Field:     of.Name,
					FullField: fullField,
				})
			}

			if of.Sequence {
				sequenceName := fmt.Sprintf("%s_%s_seq", oi.Table, colName)
				tableDef.Sequences = append(tableDef.Sequences, DMLDataTableSequence{
					Name:    sequenceName,
					ColName: colName,
					Field:   of.Name,
				})

				data.HasSequences = true
			}
		}

		data.TableDefs = append(data.TableDefs, tableDef)
	}

	return data
}

func genDMLData(gd *genData, dbType sql.Type) DMLData {
	objectsInfo := []sqlg.ObjectInfo{}
	for _, oi := range gd.ObjectsInfo {
		oi.Fields = append(objectMetaFields(), oi.Fields...)

		objectsInfo = append(objectsInfo, oi)
	}

	objectsInfo = sqlg.PopulateObjectsInfo(objectsInfo, dbType)

	data := DMLData{DBType: xstrings.FirstRuneToUpper(string(dbType)), TypesImport: gd.TypesImport, AdditionalImports: gd.AdditionalImports, HasJSON: gd.HasJSON}

	if dbType == sql.Postgres {
		data.RawInsertSuffix = "OVERRIDING SYSTEM VALUE"
	}

	for _, oi := range objectsInfo {
		tableDef := DMLDataTable{Table: oi.Table, ObjectName: oi.Name}
		tableDef.LowerTable = strings.ToLower(oi.Table)
		tableDef.LowerObjectName = strings.ToLower(oi.Name)
		tableDef.LowerCamelObjectName = strcase.ToLowerCamel(oi.Name)
		tableDef.FuncPrefix = strcase.ToLowerCamel(oi.Name)

		for _, of := range oi.Fields {
			colName := of.ColName
			insertColName := fmt.Sprintf("\"%s\"", colName)
			fullField := fmt.Sprintf("%s.%s", tableDef.LowerObjectName, of.Name)

			fieldType := of.Type
			if of.Nullable {
				fieldType = "*" + fieldType
			}

			paramName := "in" + strcase.ToCamel(of.Name)

			var funcParam string
			if of.JSON {
				funcParam = fmt.Sprintf("%s []byte", paramName)
			} else {
				funcParam = fmt.Sprintf("%s %s", paramName, fieldType)
			}

			set := fmt.Sprintf("ub.Assign(\"%s\", %s)", colName, paramName)

			var varName string
			if of.JSON {
				varName = fmt.Sprintf("%sJSON", paramName)
			} else {
				varName = fullField
			}

			if !of.Sequence || dbType == sql.Sqlite3 {
				tableDef.InsertFuncParams = append(tableDef.InsertFuncParams, funcParam)
				tableDef.InsertColumns = append(tableDef.InsertColumns, insertColName)
				tableDef.InsertValues = append(tableDef.InsertValues, paramName)
				tableDef.InsertVarNames = append(tableDef.InsertVarNames, varName)
			}
			if !of.Sequence {
				tableDef.UpdateFuncParams = append(tableDef.UpdateFuncParams, funcParam)
				tableDef.UpdateVarNames = append(tableDef.UpdateVarNames, varName)
				tableDef.UpdateSets = append(tableDef.UpdateSets, set)
				if of.JSON {
					tableDef.JSONValues = append(tableDef.JSONValues, DMLDataTableJSON{
						VarName:   paramName,
						Field:     of.Name,
						FullField: fullField,
					})
				}
			}

			tableDef.RawFuncParams = append(tableDef.RawFuncParams, funcParam)
			tableDef.RawInsertColumns = append(tableDef.RawInsertColumns, insertColName)
			tableDef.RawInsertValues = append(tableDef.RawInsertValues, paramName)
			tableDef.RawInsertVarNames = append(tableDef.RawInsertVarNames, varName)
		}

		data.TableDefs = append(data.TableDefs, tableDef)
	}

	return data
}

func genDML(gd *genData) {
	data := genDMLGenericData(gd)

	f, err := os.Create("dml.go")
	if err != nil {
		panic(err)
	}

	if err := dmlGenericTemplate.Execute(f, data); err != nil {
		panic(err)
	}

	f.Close()

	for _, dbType := range []sql.Type{sql.Postgres, sql.Sqlite3} {
		data := genDMLData(gd, dbType)

		f, err := os.Create(fmt.Sprintf("dml_%s.go", dbType))
		if err != nil {
			panic(err)
		}

		if err := dmlTemplate.Execute(f, data); err != nil {
			panic(err)
		}

		f.Close()
	}
}

var dmlGenericTemplate = template.Must(template.New("").Funcs(sprig.TxtFuncMap()).Funcs(funcs).Parse(`// Code generated by go generate; DO NOT EDIT.
package db

import (
	"encoding/json"
	"fmt"
	stdsql "database/sql"
	"time"

	"github.com/sorintlab/errors"
	sq "github.com/huandu/go-sqlbuilder"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"

	types "{{ .TypesImport -}}"
)

{{- range $tableDef := .TableDefs }}

var (
	{{ $tableDef.FuncPrefix }}SelectColumns = func(additionalCols ...string) []string {
		columns := []string{ {{- $tableDef.SelectColumns | join ", " -}} }
		columns = append(columns, additionalCols...)

		return columns
	}

	{{ $tableDef.FuncPrefix }}Select = func(additionalCols ...string) *sq.SelectBuilder {
		return sq.NewSelectBuilder().Select({{ $tableDef.FuncPrefix}}SelectColumns(additionalCols...)...).From("{{ $tableDef.Table }}")
	}
)

func (d *DB) InsertOrUpdate{{ $tableDef.ObjectName }}(tx *sql.Tx, v *types.{{ $tableDef.ObjectName }}) error {
	var err error
	if v.Revision == 0 {
		err = d.Insert{{ $tableDef.ObjectName }}(tx, v)
	} else {
		err = d.Update{{ $tableDef.ObjectName }}(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) Insert{{ $tableDef.ObjectName }}(tx *sql.Tx, v *types.{{ $tableDef.ObjectName }}) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	if v.TxID != tx.ID() {
		return errors.Errorf("object was not created by this transaction")
	}

	v.Revision = 1

	now := time.Now()
	v.CreationTime = now
	v.UpdateTime = now

	var err error

{{- if $tableDef.Sequences }}
	var nextSeq uint64
{{ end -}}
{{- range $sequence := $tableDef.Sequences }}
	nextSeq, err = d.nextSequence(tx, "{{ $sequence.Name}}")
	if err != nil {
		v.Revision = 0
		return errors.Wrap(err, "failed to create next sequence for {{ $sequence.Name }}")
	}
	v.{{ $sequence.Field }} = nextSeq
{{- end }}

	switch d.DBType() {
	case sql.Postgres:
		err = d.insertRaw{{ $tableDef.ObjectName }}Postgres(tx, v);
	case sql.Sqlite3:
		err = d.insert{{ $tableDef.ObjectName }}Sqlite3(tx, v);
	}

	if err != nil {
		v.Revision = 0
		return errors.Wrap(err, "failed to insert {{ $tableDef.Table }}")
	}

	return nil
}

func (d *DB) Update{{ $tableDef.ObjectName }}(tx *sql.Tx, v *types.{{ $tableDef.ObjectName }}) error {
	if v.Revision < 1 {
		return errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	if v.TxID != tx.ID() {
		return errors.Errorf("object was not fetched by this transaction")
	}

	curRevision := v.Revision
	v.Revision++

	v.UpdateTime = time.Now()

	var res stdsql.Result
	var err error
	switch d.DBType() {
	case sql.Postgres:
		res, err = d.update{{ $tableDef.ObjectName }}Postgres(tx, curRevision, v);
	case sql.Sqlite3:
		res, err = d.update{{ $tableDef.ObjectName }}Sqlite3(tx, curRevision, v);
	}
	if err != nil {
		v.Revision = curRevision
		return errors.Wrap(err, "failed to update {{ $tableDef.Table }}")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return errors.Wrap(err, "failed to update {{ $tableDef.Table }}")
	}

	if rows != 1 {
		v.Revision = curRevision
		return sqlg.ErrConcurrent
	}

	return nil
}

func (d *DB) delete{{$tableDef.ObjectName}}(tx *sql.Tx, {{$tableDef.FuncPrefix}}ID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("{{ $tableDef.Table }}").Where(q.E("id", {{ $tableDef.FuncPrefix }}ID))

	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete {{ $tableDef.FuncPrefix }}")
	}

	return nil
}

func (d *DB) Delete{{ $tableDef.ObjectName }}(tx *sql.Tx, id string) error {
	return d.delete{{ $tableDef.ObjectName }}(tx, id)
}

// insertRaw{{ $tableDef.ObjectName }} should be used only for import.
// * It won't update object times.
// * It will insert values for sequences.
func (d *DB) insertRaw{{ $tableDef.ObjectName }}(tx *sql.Tx, v *types.{{ $tableDef.ObjectName }}) error {
	v.Revision = 1

	var err error
	switch d.DBType() {
	case sql.Postgres:
		err = d.insertRaw{{ $tableDef.ObjectName }}Postgres(tx, v);
	case sql.Sqlite3:
		err = d.insertRaw{{ $tableDef.ObjectName }}Sqlite3(tx, v);
	}
	if err != nil {
		v.Revision = 0
		return errors.Wrap(err, "failed to insert {{ $tableDef.Table }}")
	}

	return nil
}
{{- end }}

func (d *DB) UnmarshalExportObject(data []byte) (sqlg.Object, error) {
	type exportObjectExportMeta struct {
		ExportMeta sqlg.ExportMeta {{ tick }}json:"exportMeta"{{ tick }}
	}

	var om exportObjectExportMeta
	if err := json.Unmarshal(data, &om); err != nil {
		return nil, errors.WithStack(err)
	}

	var obj sqlg.Object

	switch om.ExportMeta.Kind {
{{- range $tableDef := .TableDefs }}
	case "{{ $tableDef.ObjectName }}":
		obj = &types.{{ $tableDef.ObjectName }}{}
{{- end }}

	default:
		panic(errors.Errorf("unknown object kind %q, data: %s", om.ExportMeta.Kind, data))
	}

	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}

func (d *DB) InsertRawObject(tx *sql.Tx, obj sqlg.Object) error {
	switch o := obj.(type) {
{{- range $tableDef := .TableDefs }}
	case *types.{{ $tableDef.ObjectName }}:
		return d.insertRaw{{ $tableDef.ObjectName }}(tx, o)
{{- end }}

	default:
		panic(errors.Errorf("unknown object type %T", obj))
	}
}

func (d *DB) SelectObject(kind string) *sq.SelectBuilder {
	switch kind {
{{- range $tableDef := .TableDefs }}
	case "{{ $tableDef.ObjectName }}":
		return {{ $tableDef.LowerCamelObjectName }}Select()
{{- end }}

	default:
		panic(errors.Errorf("unknown object kind %q", kind))
	}
}

func (d *DB) FetchObjects(tx *sql.Tx, kind string, q sq.Builder) ([]sqlg.Object, error) {
	switch kind {
{{- range $tableDef := .TableDefs }}
	case "{{ $tableDef.ObjectName }}":
		fobjs, _, err := d.fetch{{ $tableDef.ObjectName }}s(tx, q)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		objs := make([]sqlg.Object, len(fobjs))
		for i, fobj := range fobjs {
		        objs[i] = fobj
		}

		return objs, nil
{{- end }}

	default:
		panic(errors.Errorf("unknown object kind %q", kind))
	}
}

func (d *DB) ObjectToExportJSON(obj sqlg.Object, e *json.Encoder) error {
	switch o := obj.(type) {
{{- range $tableDef := .TableDefs }}
	case *types.{{ $tableDef.ObjectName }}:
		type exportObject struct {
			ExportMeta sqlg.ExportMeta {{ tick }}json:"exportMeta"{{ tick }}

			*types.{{ $tableDef.ObjectName }}
		}

		if err := e.Encode(&exportObject{ExportMeta: sqlg.ExportMeta{ Kind: "{{ $tableDef.ObjectName}}" }, {{ $tableDef.ObjectName }}: o}); err != nil {
			return errors.WithStack(err)
		}

		return nil
{{- end }}

	default:
		panic(errors.Errorf("unknown object kind %T", obj))
	}
}

func (d *DB) GetSequence(tx *sql.Tx, sequenceName string) (uint64, error) {
	var q *sq.SelectBuilder

	switch d.DBType() {
	case sql.Postgres:
		q = sq.NewSelectBuilder().Select("last_value").From(sequenceName)

	case sql.Sqlite3:
		q = sq.NewSelectBuilder().Select("value").From("sequence_t")
		q.Where(q.E("name", sequenceName))
	}

	rows, err := d.query(tx, q)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	defer rows.Close()

	var value uint64
	if !rows.Next() {
		return value, nil
	}

	if err := rows.Scan(&value); err != nil {
		return 0, errors.Wrap(err, "failed to scan rows")
	}
	if err := rows.Err(); err != nil {
		return 0, errors.WithStack(err)
	}

	return value, nil
}

func (d *DB) nextSequence(tx *sql.Tx, sequenceName string) (uint64, error) {
	var value uint64

	switch d.DBType() {
	case sql.Postgres:
		q := fmt.Sprintf("SELECT nextval('%s');", sequenceName)

		rows, err := tx.Query(q)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to get sequence %s nextval", sequenceName)
		}

		defer rows.Close()

		if !rows.Next() {
			return value, nil
		}

		if err := rows.Scan(&value); err != nil {
			return 0, errors.Wrap(err, "failed to scan rows")
		}
		if err := rows.Err(); err != nil {
			return 0, errors.WithStack(err)
		}

	case sql.Sqlite3:
		var err error
		value, err = d.GetSequence(tx, sequenceName)
		if err != nil {
			return 0, errors.WithStack(err)
		}

		if value == 0 {
			value++
			q := sq.NewInsertBuilder()
			q.InsertInto("sequence_t").Cols("name", "value").Values(sequenceName, value)
			if _, err := d.exec(tx, q); err != nil {
				return 0, errors.WithStack(err)
			}
		} else {
			value++
			q := sq.NewUpdateBuilder()
			q.Update("sequence_t").Set(q.Assign("value", value)).Where(q.E("name", sequenceName))
			if _, err := d.exec(tx, q); err != nil {
				return 0, errors.WithStack(err)
			}
		}
	}

	return value, nil
}

func (d *DB) PopulateSequences(tx *sql.Tx) error {
	switch d.DBType() {
	case sql.Postgres:
		return d.populateSequencesPostgres(tx);
	case sql.Sqlite3:
		return d.populateSequencesSqlite3(tx);
	}

	return nil
}

func (d *DB) populateSequencesPostgres(tx *sql.Tx) error {
{{- if .HasSequences }}
	var q string
{{- end }}
{{- range $tableDef := .TableDefs }}
{{- range $sequence := $tableDef.Sequences }}
	q = "SELECT setval('{{ $sequence.Name }}', (SELECT COALESCE(MAX({{ $sequence.ColName }}), 1) FROM {{ $tableDef.Table }}));"
	if _, err := tx.Exec(q); err != nil {
		return errors.Wrap(err, "failed to update sequence {{ $sequence.Name}}")
	}
{{- end }}
{{- end }}

	return nil
}

func (d *DB) populateSequencesSqlite3(tx *sql.Tx) error {
{{- if .HasSequences }}
	var q string
{{- end }}
{{- range $tableDef := .TableDefs }}
{{- range $sequence := $tableDef.Sequences }}
	q = "INSERT INTO sequence_t (name, value) VALUES ('{{ $sequence.Name }}', (SELECT COALESCE(MAX({{ $sequence.ColName }}), 1) FROM {{ $tableDef.Table }}));"
	if _, err := tx.Exec(q); err != nil {
		return errors.Wrap(err, "failed to update sequence for {{ $sequence.Name }}")
	}
{{- end }}
{{- end }}

	return nil
}
`))

var dmlTemplate = template.Must(template.New("").Funcs(sprig.TxtFuncMap()).Funcs(funcs).Parse(`// Code generated by go generate; DO NOT EDIT.
package db

import (
	{{- if .HasJSON}}
	"encoding/json"
	{{- end}}
	stdsql "database/sql"
	"time"

	"github.com/sorintlab/errors"
	sq "github.com/huandu/go-sqlbuilder"

	"agola.io/agola/internal/sqlg/sql"

	types "{{ .TypesImport -}}"
)

{{- $dbType := .DBType }}
{{- $rawInsertSuffix := .RawInsertSuffix }}
{{- range $tableDef := .TableDefs }}
var (
	{{ $tableDef.FuncPrefix }}Insert{{ $dbType }} = func({{ $tableDef.InsertFuncParams | join ", " }}) *sq.InsertBuilder {
		ib:= sq.NewInsertBuilder()
		return ib.InsertInto("{{ $tableDef.Table }}").Cols({{ $tableDef.InsertColumns | join ", "}}).Values({{ $tableDef.InsertValues | join ", "}})
	}
	{{ $tableDef.FuncPrefix }}Update{{ $dbType }} = func(curRevision uint64, {{ $tableDef.UpdateFuncParams | join ", "}}) *sq.UpdateBuilder {
		ub:= sq.NewUpdateBuilder()
		return ub.Update("{{ $tableDef.Table }}").Set({{ $tableDef.UpdateSets | join ", "}}).Where(ub.E("id", inId), ub.E("revision", curRevision))
	}

	{{ $tableDef.FuncPrefix }}InsertRaw{{ $dbType }} = func({{ $tableDef.RawFuncParams | join ", "}}) *sq.InsertBuilder {
		ib:= sq.NewInsertBuilder()
		return ib.InsertInto("{{ $tableDef.Table }}").Cols({{ $tableDef.RawInsertColumns | join ", "}}).SQL("{{ $rawInsertSuffix }}").Values({{ $tableDef.RawInsertValues | join ", "}})
	}
)

func (d *DB) insert{{$tableDef.ObjectName}}{{ $dbType }}(tx *sql.Tx, {{ $tableDef.LowerObjectName }} *types.{{ $tableDef.ObjectName }}) error {
	{{- range $j := $tableDef.JSONValues }}
	{{ $j.VarName }}JSON, err := json.Marshal({{ $j.FullField }})
	if err != nil {
		return errors.Wrap(err, "failed to marshal {{ $j.FullField }}")
	}
	{{- end }}
	q := {{ $tableDef.FuncPrefix }}Insert{{ $dbType }}({{ $tableDef.InsertVarNames | join ", "}})

	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to insert {{ $tableDef.FuncPrefix }}")
	}

	return nil
}

func (d *DB) update{{$tableDef.ObjectName}}{{ $dbType }}(tx *sql.Tx, curRevision uint64, {{ $tableDef.LowerObjectName }} *types.{{ $tableDef.ObjectName }}) (stdsql.Result, error) {
	{{- range $j := $tableDef.JSONValues }}
	{{ $j.VarName }}JSON, err := json.Marshal({{ $j.FullField }})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal {{ $j.FullField }}")
	}
	{{- end }}
	q := {{ $tableDef.FuncPrefix }}Update{{ $dbType }}(curRevision, {{ $tableDef.UpdateVarNames | join ", "}})

	res, err := d.exec(tx, q)
	if err != nil {
		return nil, errors.Wrap(err, "failed to update {{ $tableDef.FuncPrefix }}")
	}

	return res, nil
}

func (d *DB) insertRaw{{$tableDef.ObjectName}}{{ $dbType }}(tx *sql.Tx, {{ $tableDef.LowerObjectName }} *types.{{ $tableDef.ObjectName }}) error {
	{{- range $j := $tableDef.JSONValues }}
	{{ $j.VarName }}JSON, err := json.Marshal({{ $j.FullField }})
	if err != nil {
		return errors.Wrap(err, "failed to marshal {{ $j.FullField }}")
	}
	{{- end }}
	q := {{ $tableDef.FuncPrefix }}InsertRaw{{ $dbType }}({{ $tableDef.RawInsertVarNames | join ", "}})

	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to insert {{ $tableDef.FuncPrefix }}")
	}

	return nil
}

{{- end }}
`))
