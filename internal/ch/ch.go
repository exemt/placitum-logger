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
		/*
		 * Обе настройки -- про FINAL, которым читают счёт, группы и карточку.
		 *
		 * use_skip_indexes_if_final: в 24.8 под FINAL skip-индексы выключены --
		 * ClickHouse боится пропустить гранулу, где лежит более свежая версия
		 * строки, и отдать старую. У нас версий нет: rev всегда 0, повторная
		 * доставка кладёт ту же строку байт в байт, и гранула без искомого
		 * значения не содержит его ни в одной копии. Без настройки ни один
		 * bloom- и ngram-индекс таблиц не работал вовсе.
		 *
		 * do_not_merge_across_partitions_select_final: FINAL сводит каждую
		 * партицию отдельно, не пересекая их. Безопасно, потому что строки с
		 * одним ключом не могут лечь в разные партиции: партиция -- день ts,
		 * а ts -- первая колонка ключа (schema/024).
		 */
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
