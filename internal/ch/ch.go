package ch

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

func Open() (driver.Conn, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{env("CLICKHOUSE_ADDR", "127.0.0.1:9000")},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: env("CLICKHOUSE_USER", "waf"),
			Password: env("CLICKHOUSE_PASSWORD", "waf"),
		},
		DialTimeout: 5 * time.Second,
		Settings: clickhouse.Settings{
			"use_skip_indexes_if_final":                   1,
			"do_not_merge_across_partitions_select_final": 1,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	return conn, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
