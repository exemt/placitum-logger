package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const versionsTable = `
CREATE TABLE IF NOT EXISTS waf.schema_migrations
(
    version    String,
    applied_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY version
`

const lockTable = `
CREATE TABLE waf.schema_lock
(
    holder String,
    beat   DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY beat
`

const (
	codeTableExists = 57

	lockBeat  = 15 * time.Second
	lockStale = 2 * time.Minute
	lockPoll  = 2 * time.Second
)

func Apply(ctx context.Context, conn driver.Conn, dir string) error {
	if err := conn.Exec(ctx, "CREATE DATABASE IF NOT EXISTS waf"); err != nil {
		return fmt.Errorf("create database: %w", err)
	}

	unlock, err := lock(ctx, conn)
	if err != nil {
		return err
	}
	defer unlock()

	if err := conn.Exec(ctx, versionsTable); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}

	files, err := list(dir)
	if err != nil {
		return err
	}

	done, err := applied(ctx, conn)
	if err != nil {
		return err
	}

	for _, name := range files {
		if done[name] {
			continue
		}

		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		sql := strings.TrimSpace(expand(string(body)))
		if sql == "" {
			continue
		}

		if err := conn.Exec(ctx, sql); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		if err := conn.Exec(ctx,
			"INSERT INTO waf.schema_migrations (version) VALUES (?)", name); err != nil {
			return fmt.Errorf("%s: record: %w", name, err)
		}
	}

	return nil
}

func lock(ctx context.Context, conn driver.Conn) (func(), error) {
	holder, _ := os.Hostname()

	for {
		err := conn.Exec(ctx, lockTable)
		if err == nil {
			break
		}

		var ex *clickhouse.Exception
		if !errors.As(err, &ex) || ex.Code != codeTableExists {
			return nil, fmt.Errorf("schema_lock: %w", err)
		}

		stale, err := lockIsStale(ctx, conn)
		if err != nil {
			return nil, err
		}

		if stale {
			if err := conn.Exec(ctx, "DROP TABLE IF EXISTS waf.schema_lock"); err != nil {
				return nil, fmt.Errorf("schema_lock: drop stale: %w", err)
			}

			continue
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("schema_lock: %w", ctx.Err())
		case <-time.After(lockPoll):
		}
	}

	beatCtx, stop := context.WithCancel(ctx)
	beat(beatCtx, conn, holder)

	go func() {
		t := time.NewTicker(lockBeat)
		defer t.Stop()

		for {
			select {
			case <-beatCtx.Done():
				return
			case <-t.C:
				beat(beatCtx, conn, holder)
			}
		}
	}()

	return func() {
		stop()

		dropCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = conn.Exec(dropCtx, "DROP TABLE IF EXISTS waf.schema_lock")
	}, nil
}

func beat(ctx context.Context, conn driver.Conn, holder string) {
	_ = conn.Exec(ctx, "INSERT INTO waf.schema_lock (holder) VALUES (?)", holder)
}

func lockIsStale(ctx context.Context, conn driver.Conn) (bool, error) {
	var age float64

	err := conn.QueryRow(ctx,
		"SELECT if(count() = 0, 1e9, toFloat64(now() - max(beat))) FROM waf.schema_lock").
		Scan(&age)
	if err != nil {
		var ex *clickhouse.Exception
		if errors.As(err, &ex) && ex.Code == codeUnknownTable {
			return true, nil
		}

		return false, fmt.Errorf("schema_lock: age: %w", err)
	}

	return age > lockStale.Seconds(), nil
}

const codeUnknownTable = 60

func list(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("schema dir: %w", err)
	}

	var names []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}

		names = append(names, e.Name())
	}

	sort.Strings(names)

	return names, nil
}

func applied(ctx context.Context, conn driver.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, "SELECT version FROM waf.schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	defer rows.Close()

	out := map[string]bool{}

	for rows.Next() {
		var v string

		if err := rows.Scan(&v); err != nil {
			return nil, err
		}

		out[v] = true
	}

	return out, rows.Err()
}

var subst = map[string]string{
	"POSTGRES_HOST":     "postgres",
	"POSTGRES_PORT":     "5432",
	"POSTGRES_USER":     "waf",
	"POSTGRES_PASSWORD": "waf",
	"POSTGRES_DB":       "waf",
}

func expand(sql string) string {
	for key, fallback := range subst {
		value := os.Getenv(key)
		if value == "" {
			value = fallback
		}

		sql = strings.ReplaceAll(sql, "${"+key+"}", value)
	}

	return sql
}
