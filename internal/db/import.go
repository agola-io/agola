package db

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"

	"github.com/rs/zerolog"
)

func Import(ctx context.Context, log zerolog.Logger, d DB, r io.Reader) error {
	br := bufio.NewReader(r)
	dec := json.NewDecoder(br)

	err := d.Do(ctx, func(tx *sql.Tx) error {
		for _, oi := range d.ObjectsInfo() {
			if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s", oi.Table)); err != nil {
				return errors.Wrapf(err, "failed to drop table %s", oi.Table)
			}
		}

		for _, stmt := range d.DTablesStatements() {
			if _, err := tx.Exec(stmt); err != nil {
				return errors.Wrap(err, "statement failed")
			}
		}

		for {
			var jobj json.RawMessage

			err := dec.Decode(&jobj)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return errors.WithStack(err)
			}

			obj, err := d.UnmarshalObject(jobj)
			if err != nil {
				return errors.WithStack(err)
			}

			if _, err := d.InsertRawObject(tx, obj); err != nil {
				return errors.WithStack(err)
			}
		}
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
