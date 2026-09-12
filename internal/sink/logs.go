package sink

import (
	"context"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/model"
)

const insertLogSQL = `INSERT INTO waf.log (
	ts, writer, service, severity, text
)`

func InsertLogs(ctx context.Context, conn driver.Conn, rows []model.LogRow) error {
	if len(rows) == 0 {
		return nil
	}

	batch, err := conn.PrepareBatch(ctx, insertLogSQL)
	if err != nil {
		return fmt.Errorf("prepare log: %w", err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.TS,
			row.Writer,
			row.Service,
			row.Severity,
			row.Text,
		); err != nil {
			return fmt.Errorf("append log: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send log: %w", err)
	}

	return nil
}
