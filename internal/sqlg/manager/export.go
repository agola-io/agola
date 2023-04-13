package manager

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg/sql"
)

func (m *DBManager) Export(ctx context.Context, objectKinds []string, w io.Writer) error {
	bw := bufio.NewWriter(w)
	e := json.NewEncoder(bw)

	err := m.d.Do(ctx, func(tx *sql.Tx) error {
		for _, objectKind := range objectKinds {
			var curStartID string

			for {
				q := m.d.SelectObject(objectKind).OrderBy("id asc")
				q = q.Where(q.G("id", curStartID))
				q = q.Limit(MaxQueryLimit)

				objs, err := m.d.FetchObjects(tx, objectKind, q)
				if err != nil {
					return errors.WithStack(err)
				}

				var lastID string
				for _, obj := range objs {
					if err := m.d.ObjectToExportJSON(obj, e); err != nil {
						return errors.WithStack(err)
					}

					lastID = obj.GetID()
				}

				if len(objs) < MaxQueryLimit {
					break
				}

				curStartID = lastID
			}
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(bw.Flush())
}
