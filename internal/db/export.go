package db

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/rs/zerolog"
)

func Export(ctx context.Context, log zerolog.Logger, d DB, w io.Writer) error {
	bw := bufio.NewWriter(w)

	err := d.Do(ctx, func(tx *sql.Tx) error {
		for _, oi := range d.ObjectsInfo() {
			var curStartID string

			for {
				idEntry := fmt.Sprintf("%s.id", oi.Table)
				revisionEntry := fmt.Sprintf("%s.revision", oi.Table)
				dataEntry := fmt.Sprintf("%s.data", oi.Table)
				q := sb.Select(idEntry, revisionEntry, dataEntry).From(oi.Table).OrderBy("id asc")
				q = q.Where(sq.Gt{idEntry: curStartID})
				q = q.Limit(MaxQueryLimit)

				rows, err := d.Query(tx, q)
				if err != nil {
					return errors.WithStack(err)
				}

				datas := []ObjectData{}
				for rows.Next() {
					var id string
					var revision uint64
					var data []byte
					if err := rows.Scan(&id, &revision, &data); err != nil {
						rows.Close()
						return errors.Wrap(err, "failed to scan rows")
					}
					datas = append(datas, ObjectData{
						id:       id,
						revision: revision,
						data:     data,
					})
				}

				var lastID string
				for _, data := range datas {
					if _, err := bw.Write(data.data); err != nil {
						return errors.WithStack(err)
					}
					if _, err := bw.WriteString("\n"); err != nil {
						return errors.WithStack(err)
					}

					lastID = data.id
				}

				if len(datas) < MaxQueryLimit {
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
