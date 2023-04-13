package manager

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg/sql"
)

func (m *DBManager) Import(ctx context.Context, r io.Reader) error {
	br := bufio.NewReader(r)
	dec := json.NewDecoder(br)

	err := m.d.Do(ctx, func(tx *sql.Tx) error {
		// TODO(sgotti) check for tables with data and return an error

		for {
			var jobj json.RawMessage

			err := dec.Decode(&jobj)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errors.WithStack(err)
			}

			obj, err := m.d.UnmarshalExportObject(jobj)
			if err != nil {
				return errors.WithStack(err)
			}

			if err := m.d.InsertRawObject(tx, obj); err != nil {
				return errors.WithStack(err)
			}
		}

		// Populate sequences
		if err := m.d.PopulateSequences(tx); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
