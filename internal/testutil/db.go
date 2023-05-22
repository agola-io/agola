package testutil

import (
	"bufio"
	"bytes"
	"context"
	stdsql "database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	atlasschema "ariga.io/atlas/sql/schema"
	atlassqlclient "ariga.io/atlas/sql/sqlclient"
	"github.com/google/go-cmp/cmp/cmpopts"
	sq "github.com/huandu/go-sqlbuilder"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"muzzammil.xyz/jsonc"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"

	_ "ariga.io/atlas/sql/postgres"
	_ "ariga.io/atlas/sql/postgres/postgrescheck"
	_ "ariga.io/atlas/sql/sqlite"
	_ "ariga.io/atlas/sql/sqlite/sqlitecheck"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func DBType(t *testing.T) sql.Type {
	var dbType sql.Type
	switch os.Getenv("DB_TYPE") {
	case "":
		fallthrough
	case "sqlite3":
		dbType = sql.Sqlite3
	case "postgres":
		dbType = sql.Postgres
	default:
		t.Fatalf("unknown db type")
	}

	return dbType
}

func CreateDB(t *testing.T, log zerolog.Logger, ctx context.Context, dir string) (*sql.DB, lock.LockFactory, string) {
	dbType := DBType(t)

	return CreateDBWithType(t, log, ctx, dir, dbType)
}

func CreateDBWithType(t *testing.T, log zerolog.Logger, ctx context.Context, dir string, dbType sql.Type) (*sql.DB, lock.LockFactory, string) {
	pgConnString := os.Getenv("PG_CONNSTRING")

	var err error
	var sdb *sql.DB
	var connString string

	switch dbType {
	case sql.Sqlite3:
		dbName := "testdb" + strconv.FormatUint(uint64(rand.Uint32()), 10)
		connString = filepath.Join(dir, dbName)

		sdb, err = sql.NewDB("sqlite3", connString)
		assert.NilError(t, err)

	case sql.Postgres:
		dbName := "testdb" + strconv.FormatUint(uint64(rand.Uint32()), 10)
		connString = fmt.Sprintf(pgConnString, dbName)

		pgdb, err := stdsql.Open("postgres", fmt.Sprintf(pgConnString, "postgres"))
		assert.NilError(t, err)

		_, err = pgdb.Exec(fmt.Sprintf("drop database if exists %s", dbName))
		assert.NilError(t, err)

		_, err = pgdb.Exec(fmt.Sprintf("create database %s", dbName))
		assert.NilError(t, err)

		sdb, err = sql.NewDB("postgres", connString)
		assert.NilError(t, err)

	default:
		t.Fatalf("unknown db type")
	}

	var lf lock.LockFactory
	switch dbType {
	case sql.Sqlite3:
		ll := lock.NewLocalLocks()
		lf = lock.NewLocalLockFactory(ll)
	case sql.Postgres:
		lf = lock.NewPGLockFactory(sdb)
	default:
		t.Fatalf("unknown type %q", dbType)
	}

	return sdb, lf, connString
}

type DBContext struct {
	D            manager.DB
	DBM          *manager.DBManager
	LF           lock.LockFactory
	DBConnString string
	Schema       []TableInfo
}

func (c *DBContext) AtlasConnString() string {
	switch c.D.DBType() {
	case sql.Postgres:
		return c.DBConnString
	case sql.Sqlite3:
		return fmt.Sprintf("sqlite://%s", c.DBConnString)
	}

	return ""
}

func (c *DBContext) Tables() []string {
	tables := []string{}
	for _, table := range c.Schema {
		tables = append(tables, table.Name)
	}

	return tables
}

func (c *DBContext) Table(tableName string) (TableInfo, bool) {
	for _, table := range c.Schema {
		if table.Name == tableName {
			return table, true
		}
	}

	return TableInfo{}, false
}

func (c *DBContext) Column(tableName, colName string) (ColInfo, bool) {
	ti, ok := c.Table(tableName)
	if !ok {
		return ColInfo{}, false
	}

	for _, ci := range ti.Columns {
		if ci.Name == colName {
			return ci, true
		}
	}

	return ColInfo{}, false
}

type ColType int

const (
	ColTypeString ColType = iota
	ColTypeBool
	ColTypeInt
	ColTypeFloat
	ColTypeTime
	ColTypeDuration
	ColTypeJSON
)

func (c *DBContext) ColumnType(tableName, colName string) (ColType, error) {
	col, ok := c.Column(tableName, colName)
	if !ok {
		return 0, errors.Errorf("unknown column %q.%q", tableName, colName)
	}

	switch col.Type {
	case "string":
		return ColTypeString, nil
	case "bool":
		return ColTypeBool, nil
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "byte", "rune":
		return ColTypeInt, nil
	case "float32", "float64":
		return ColTypeFloat, nil
	case "time.Time":
		return ColTypeTime, nil
	case "time.Duration":
		return ColTypeDuration, nil
	case "json":
		return ColTypeJSON, nil

	default:
		panic(fmt.Errorf("unknown col type: %q", col.Type))
	}
}

type importData struct {
	Table  string
	Values map[string]json.RawMessage
}

type exportData struct {
	Table  string
	Values map[string]any
}

func (c *DBContext) sqFlavor() sq.Flavor {
	switch c.D.DBType() {
	case sql.Postgres:
		return sq.PostgreSQL
	case sql.Sqlite3:
		return sq.SQLite
	}

	return sq.PostgreSQL
}

func (c *DBContext) exec(tx *sql.Tx, rq sq.Builder) (stdsql.Result, error) {
	q, args := rq.BuildWithFlavor(c.sqFlavor())

	r, err := tx.Exec(q, args...)
	return r, errors.WithStack(err)
}

func (c *DBContext) query(tx *sql.Tx, rq sq.Builder) (*stdsql.Rows, error) {
	q, args := rq.BuildWithFlavor(c.sqFlavor())

	r, err := tx.Query(q, args...)
	return r, errors.WithStack(err)
}

func (c *DBContext) Import(ctx context.Context, r io.Reader) error {
	br := bufio.NewReader(r)
	dec := json.NewDecoder(br)

	err := c.D.Do(ctx, func(tx *sql.Tx) error {
		for {
			var data importData

			err := dec.Decode(&data)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errors.WithStack(err)
			}

			tableName := data.Table

			for colName := range data.Values {
				// check if column exists in schema
				if _, err := c.ColumnType(tableName, colName); err != nil {
					return errors.WithStack(err)
				}
			}

			table, ok := c.Table(tableName)
			if !ok {
				return errors.Errorf("unknown table %q", tableName)
			}

			cols := []string{}
			values := []any{}
			for _, col := range table.Columns {
				colName := col.Name
				cols = append(cols, colName)

				if colName == "revision" {
					values = append(values, 1)
					continue
				}

				v, hasValue := data.Values[colName]

				colType, err := c.ColumnType(tableName, colName)
				if err != nil {
					return errors.WithStack(err)
				}

				switch colType {
				case ColTypeString:
					if !hasValue {
						values = append(values, "")
					} else {
						var s string
						if err := json.Unmarshal(v, &s); err != nil {
							return errors.WithStack(err)
						}
						values = append(values, s)

					}
				case ColTypeInt:
					if !hasValue {
						values = append(values, "")
					} else {
						var n int64
						if err := json.Unmarshal(v, &n); err != nil {
							return errors.WithStack(err)
						}
						values = append(values, n)
					}
				case ColTypeFloat:
					if !hasValue {
						values = append(values, "")
					} else {
						var n float64
						if err := json.Unmarshal(v, &n); err != nil {
							return errors.WithStack(err)
						}
						values = append(values, n)
					}
				case ColTypeBool:
					if !hasValue {
						values = append(values, false)
					} else {
						values = append(values, v)
					}
				case ColTypeTime:
					if !hasValue {
						values = append(values, time.Time{})
					} else {
						t := time.Time{}
						if err := t.UnmarshalJSON(v); err != nil {
							return errors.WithStack(err)
						}
						values = append(values, t)
					}
				case ColTypeDuration:
					if !hasValue {
						values = append(values, 0)
					} else {
						var d int64
						if err := json.Unmarshal(v, &d); err != nil {
							return errors.WithStack(err)
						}
						values = append(values, d)
					}
				case ColTypeJSON:
					if !hasValue {
						v = json.RawMessage("null")
					}
					vj, err := json.Marshal(v)
					if err != nil {
						return errors.WithStack(err)
					}
					values = append(values, vj)
				default:
					values = append(values, v)
				}
			}

			q := sq.NewInsertBuilder()
			q.InsertInto(tableName).Cols(cols...).Values(values...)

			if _, err := c.exec(tx, q); err != nil {
				return errors.WithStack(err)
			}
		}

		// Populate sequences
		for _, seq := range c.D.Sequences() {
			switch c.D.DBType() {
			case sql.Postgres:
				q := fmt.Sprintf("SELECT setval('%s', (SELECT COALESCE(MAX(%s), 1) FROM %s));", seq.Name, seq.Column, seq.Table)
				if _, err := tx.Exec(q); err != nil {
					return errors.Wrapf(err, "failed to update sequence %s", seq.Name)
				}

			case sql.Sqlite3:
				q := fmt.Sprintf("INSERT INTO sequence_t (name, value) VALUES ('%s', (SELECT COALESCE(MAX(%s), 1) FROM %s));", seq.Name, seq.Column, seq.Table)
				if _, err := tx.Exec(q); err != nil {
					return errors.Wrap(err, "failed to update sequence for run_sequence_seq")
				}
			}
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (c *DBContext) Export(ctx context.Context, tables []string, w io.Writer) error {
	bw := bufio.NewWriter(w)
	e := json.NewEncoder(bw)

	err := c.D.Do(ctx, func(tx *sql.Tx) error {
		for _, table := range tables {
			q := sq.NewSelectBuilder()
			q.Select("*")
			q.From(table)
			q.OrderBy("id")

			rows, err := c.query(tx, q)
			if err != nil {
				return errors.WithStack(err)
			}

			columns, err := rows.Columns()
			if err != nil {
				return errors.WithStack(err)
			}
			cols := make([]any, len(columns))
			colsPtr := make([]any, len(columns))
			for i := range cols {
				colsPtr[i] = &cols[i]
			}
			for rows.Next() {
				err := rows.Scan(colsPtr...)
				if err != nil {
					rows.Close()
					return errors.WithStack(err)
				}
				var data exportData
				data.Table = table
				data.Values = make(map[string]any)
				for i, col := range columns {
					v := cols[i]

					colType, err := c.ColumnType(data.Table, col)
					if err != nil {
						return errors.WithStack(err)
					}
					switch colType {
					case ColTypeJSON:
						var vj any
						if err := json.Unmarshal(v.([]byte), &vj); err != nil {
							return errors.WithStack(err)
						}
						data.Values[col] = vj
					default:
						data.Values[col] = v
					}
				}

				if err := e.Encode(data); err != nil {
					return errors.WithStack(err)
				}
			}
			if err := rows.Err(); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(bw.Flush())
}

type SetupDBFn func(ctx context.Context, t *testing.T, dir string) *DBContext

type CreateData struct {
	DDL       DDL         `json:"ddl"`
	Sequences []Sequence  `json:"sequences"`
	Tables    []TableInfo `json:"tables"`
}

type DDL struct {
	Postgres []string `json:"postgres"`
	Sqlite3  []string `json:"sqlite3"`
}

type TableInfo struct {
	Name    string    `json:"name"`
	Columns []ColInfo `json:"columns"`
}

type ColInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

type Sequence struct {
	Name   string `json:"name"`
	Table  string `json:"table"`
	Column string `json:"column"`
}

type DataFixtures map[uint]string

func TestCreate(t *testing.T, lastVersion uint, dataFixtures DataFixtures, setupDBFn SetupDBFn) {
	startVersion := uint(1)

	for createVersion := startVersion; createVersion <= lastVersion; createVersion++ {
		t.Run(fmt.Sprintf("create db at version %d", createVersion), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			dc := setupDBFn(ctx, t, dir)

			dataFixtureFile, ok := dataFixtures[createVersion]
			if !ok {
				t.Fatalf("missing fixture for db version %d", createVersion)
			}
			dataFixture, err := os.ReadFile(filepath.Join("fixtures", "migrate", dataFixtureFile))
			assert.NilError(t, err)
			dataFixture = jsonc.ToJSON(dataFixture)

			createFixtureFile := fmt.Sprintf("v%d.json", createVersion)
			createFixture, err := os.ReadFile(filepath.Join("fixtures", "create", createFixtureFile))
			assert.NilError(t, err)

			var createData *CreateData
			err = json.Unmarshal(createFixture, &createData)
			assert.NilError(t, err)

			dc.Schema = createData.Tables
			ddl := createData.DDL

			var stmts []string
			switch dc.D.DBType() {
			case sql.Postgres:
				stmts = ddl.Postgres
			case sql.Sqlite3:
				stmts = ddl.Sqlite3
			}

			err = dc.DBM.Setup(ctx)
			assert.NilError(t, err, "setup db error")

			err = dc.DBM.Create(ctx, stmts, createVersion)
			assert.NilError(t, err)

			err = dc.Import(ctx, bytes.NewBuffer(dataFixture))
			assert.NilError(t, err)
		})
	}
}

func TestMigrate(t *testing.T, lastVersion uint, dataFixtures DataFixtures, setupDBFn SetupDBFn) {
	startVersion := uint(1)
	// check all versions are available
	for createVersion := startVersion; createVersion < lastVersion; createVersion++ {
		if _, ok := dataFixtures[createVersion]; !ok {
			t.Fatalf("missing test import fixtures for version %d", createVersion)
		}
	}

	for createVersion := startVersion; createVersion < lastVersion; createVersion++ {
		for migrateVersion := createVersion + 1; migrateVersion <= lastVersion; migrateVersion++ {
			t.Run(fmt.Sprintf("migrate db from version %d to version %d", createVersion, migrateVersion), func(t *testing.T) {
				dir := t.TempDir()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				// create db at migrate version. For diff from migrated version.
				createDC := setupDBFn(ctx, t, dir)

				dataFixtureFileCreate, ok := dataFixtures[migrateVersion]
				if !ok {
					t.Fatalf("missing data fixture for db version %d", migrateVersion)
				}
				dataFixtureCreate, err := os.ReadFile(filepath.Join("fixtures", "migrate", dataFixtureFileCreate))
				assert.NilError(t, err)
				dataFixtureCreate = jsonc.ToJSON(dataFixtureCreate)

				createFixtureFileCreate := fmt.Sprintf("v%d.json", migrateVersion)
				createFixtureCreate, err := os.ReadFile(filepath.Join("fixtures", "create", createFixtureFileCreate))
				assert.NilError(t, err)

				var createDataCreate *CreateData
				err = json.Unmarshal(createFixtureCreate, &createDataCreate)
				assert.NilError(t, err)

				createDC.Schema = createDataCreate.Tables
				createDDL := createDataCreate.DDL

				var createStmts []string
				switch createDC.D.DBType() {
				case sql.Postgres:
					createStmts = createDDL.Postgres
				case sql.Sqlite3:
					createStmts = createDDL.Sqlite3
				}

				err = createDC.DBM.Setup(ctx)
				assert.NilError(t, err, "setup db error")

				err = createDC.DBM.Create(ctx, createStmts, migrateVersion)
				assert.NilError(t, err)

				err = createDC.Import(ctx, bytes.NewBuffer(dataFixtureCreate))
				assert.NilError(t, err)

				// create db at create version to be migrated.
				dc := setupDBFn(ctx, t, dir)
				dataFixtureFile, ok := dataFixtures[createVersion]
				if !ok {
					t.Fatalf("missing fixture for db version %d", createVersion)
				}
				dataFixture, err := os.ReadFile(filepath.Join("fixtures", "migrate", dataFixtureFile))
				assert.NilError(t, err)
				dataFixture = jsonc.ToJSON(dataFixture)

				createFixtureFile := fmt.Sprintf("v%d.json", createVersion)
				createFixture, err := os.ReadFile(filepath.Join("fixtures", "create", createFixtureFile))
				assert.NilError(t, err)

				var createData *CreateData
				err = json.Unmarshal(createFixture, &createData)
				assert.NilError(t, err)

				dc.Schema = createData.Tables
				ddl := createData.DDL

				var stmts []string
				switch dc.D.DBType() {
				case sql.Postgres:
					stmts = ddl.Postgres
				case sql.Sqlite3:
					stmts = ddl.Sqlite3
				}

				err = dc.DBM.Setup(ctx)
				assert.NilError(t, err, "setup db error")

				err = dc.DBM.Create(ctx, stmts, createVersion)
				assert.NilError(t, err)

				err = dc.Import(ctx, bytes.NewBuffer(dataFixture))
				assert.NilError(t, err)

				err = dc.DBM.MigrateToVersion(ctx, migrateVersion)
				assert.NilError(t, err)

				// Diff created and migrated schema
				createAtlasClient, err := atlassqlclient.Open(ctx, createDC.AtlasConnString())
				assert.NilError(t, err)

				atlasClient, err := atlassqlclient.Open(ctx, dc.AtlasConnString())
				assert.NilError(t, err)

				createSchema, err := createAtlasClient.InspectSchema(ctx, "", nil)
				assert.NilError(t, err)

				schema, err := atlasClient.InspectSchema(ctx, "", nil)
				assert.NilError(t, err)

				diff, err := atlasClient.SchemaDiff(createSchema, schema)
				assert.NilError(t, err)

				assert.Assert(t, len(diff) == 0, "schema of db created at version %d and db migrated from version %d to version %d is different:\n %s", migrateVersion, createVersion, migrateVersion, diff)

				createExport := &bytes.Buffer{}
				export := &bytes.Buffer{}

				tableNames := func(schema *atlasschema.Schema) []string {
					tableNames := []string{}
					for _, table := range schema.Tables {
						if table.Name == "dbversion" || table.Name == "sequence_t" {
							continue
						}
						tableNames = append(tableNames, table.Name)
					}

					sort.Strings(tableNames)

					return tableNames
				}

				err = createDC.Export(ctx, tableNames(createSchema), createExport)
				assert.NilError(t, err)

				err = dc.Export(ctx, tableNames(schema), export)
				assert.NilError(t, err)

				// Diff database data

				// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
				assert.DeepEqual(t, createExport.Bytes(), export.Bytes(), cmpopts.EquateApproxTime(1*time.Microsecond))
			})
		}
	}
}

func decodeExport(t *testing.T, d manager.DB, export []byte) []any {
	dec := json.NewDecoder(bytes.NewReader(export))

	objs := []any{}

	for {
		var jobj json.RawMessage

		err := dec.Decode(&jobj)
		if errors.Is(err, io.EOF) {
			break
		}
		assert.NilError(t, err)

		obj, err := d.UnmarshalExportObject(jobj)
		assert.NilError(t, err)

		objs = append(objs, obj)
	}

	// sort objects by id
	sort.Slice(objs, func(i, j int) bool {
		o1 := objs[i].(sqlg.Object)
		o2 := objs[j].(sqlg.Object)
		return o1.GetID() < o2.GetID()
	})

	return objs
}

func TestImportExport(t *testing.T, importFixtureFile string, setupDBFn SetupDBFn, seqs map[string]uint64) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dc := setupDBFn(ctx, t, dir)

	fixture, err := os.ReadFile(filepath.Join("fixtures", "import", importFixtureFile))
	assert.NilError(t, err)

	stmts := dc.D.DDL()

	err = dc.DBM.Create(ctx, stmts, dc.D.Version())
	assert.NilError(t, err)

	err = dc.DBM.Import(ctx, bytes.NewBuffer(fixture))
	assert.NilError(t, err)

	// check sequences
	curSeqs := map[string]uint64{}

	err = dc.D.Do(ctx, func(tx *sql.Tx) error {
		for _, seq := range dc.D.Sequences() {
			var err error

			seqValue, err := dc.D.GetSequence(tx, seq.Name)
			if err != nil {
				return errors.WithStack(err)
			}

			curSeqs[seq.Name] = seqValue
		}

		return nil
	})
	assert.NilError(t, err)

	assert.DeepEqual(t, curSeqs, seqs)

	export := &bytes.Buffer{}

	err = dc.DBM.Export(ctx, sqlg.ObjectNames(dc.D.ObjectsInfo()), export)
	assert.NilError(t, err)

	exportMap := decodeExport(t, dc.D, export.Bytes())
	fixturesMap := decodeExport(t, dc.D, fixture)

	// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
	assert.DeepEqual(t, fixturesMap, exportMap, cmpopts.EquateApproxTime(1*time.Microsecond))
}
