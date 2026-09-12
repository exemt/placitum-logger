/*
 * Поиск по waf.log. Три фильтра и окно, больше в журнале спрашивать нечего.
 *
 * Writer и service -- точное совпадение: наборы закрытые и короткие, и
 * подстрока по ним нашла бы edge-01 в edge-011. Текст -- только подстрока: имени
 * у строки лога нет, и точное сравнение с ней бессмысленно.
 *
 * Фильтры плейсхолдерами, не склейкой SQL, -- как и на позвоночнике.
 */

package query

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const logCols = `ts, writer, service, severity, text`

/*
 * FINAL здесь нет и быть не может: waf.log -- MergeTree, у строки лога нет
 * естественного ключа, и схлопывать по содержимому означало бы терять
 * повторяющиеся строки. Повтор пачки при сорванной вставке виден как повтор,
 * см. schema/013_log.sql.
 */
const logFrom = " FROM waf.log"

type LogFilter struct {
	From     time.Time
	To       time.Time
	Writer   string
	Service  string
	Severity string
	Text     string

	Limit  int
	Offset int
}

type LogLine struct {
	TS       time.Time `json:"ts"`
	Writer   string    `json:"writer"`
	Service  string    `json:"service"`
	Severity string    `json:"severity,omitempty"`
	Text     string    `json:"text"`
}

// LogFacet — пара «кто писал» и «что за сервис», встреченная в окне. Наборы
// закрытые, поэтому фильтры в UX -- списки, а не поля ввода; счётчик рядом,
// потому что он и так посчитан группировкой.
type LogFacet struct {
	Writer  string `json:"writer"`
	Service string `json:"service"`
	Count   uint64 `json:"count"`
}

// maxTextQuery — длиннее искать в строке лога незачем: ngram-индекс на длинной
// игле не выигрывает ничего, а сама строка ограничена килобайтами.
const maxTextQuery = 256

// maxLogName — потолок имени ноды и сервиса. Больше — это не имя, а попытка
// раздуть запрос; от инъекции защищает привязка, не этот предел.
const maxLogName = 128

func NormalizeLog(f LogFilter) LogFilter {
	if f.Limit <= 0 {
		f.Limit = 100
	}

	if f.Limit > 500 {
		f.Limit = 500
	}

	if f.Offset < 0 {
		f.Offset = 0
	}

	f.Writer = clampName(f.Writer)
	f.Service = clampName(f.Service)
	f.Severity = clampName(f.Severity)

	f.Text = strings.TrimSpace(f.Text)
	if len(f.Text) > maxTextQuery {
		f.Text = f.Text[:maxTextQuery]
	}

	if f.To.IsZero() {
		f.To = time.Now().UTC()
	}

	if f.From.IsZero() {
		f.From = f.To.Add(-24 * time.Hour)
	}

	return f
}

func clampName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLogName {
		return ""
	}

	return s
}

func logWhere(f LogFilter) (clauses []string, args []any) {
	add := func(clause, name string, v any) {
		clauses = append(clauses, clause)
		args = append(args, clickhouse.Named(name, v))
	}

	add("ts >= @from", "from", f.From)
	add("ts <= @to", "to", f.To)

	if f.Writer != "" {
		add("writer = @writer", "writer", f.Writer)
	}

	if f.Service != "" {
		add("service = @service", "service", f.Service)
	}

	if f.Severity != "" {
		add("severity = @severity", "severity", f.Severity)
	}

	if f.Text != "" {
		/*
		 * Именно LIKE по lower(text): выражение обязано совпадать с выражением
		 * индекса idx_text, иначе ngrambf не включится и запрос прочитает все
		 * куски партиции. positionCaseInsensitive для планировщика -- другая
		 * функция.
		 */
		add("lower(text) LIKE @text", "text",
			"%"+escapeLike(strings.ToLower(f.Text))+"%")
	}

	return clauses, args
}

func ListLogs(ctx context.Context, conn driver.Conn, f LogFilter) ([]LogLine, error) {
	f = NormalizeLog(f)
	clauses, args := logWhere(f)

	sql := "SELECT " + logCols + logFrom + whereClause(clauses) +
		" ORDER BY ts DESC LIMIT @limit OFFSET @offset"
	args = append(args,
		clickhouse.Named("limit", f.Limit),
		clickhouse.Named("offset", f.Offset),
	)

	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("logs query: %w", err)
	}
	defer rows.Close()

	out := make([]LogLine, 0, f.Limit)

	for rows.Next() {
		var line LogLine

		if err := rows.Scan(
			&line.TS,
			&line.Writer,
			&line.Service,
			&line.Severity,
			&line.Text,
		); err != nil {
			return nil, err
		}

		out = append(out, line)
	}

	return out, rows.Err()
}

func CountLogs(ctx context.Context, conn driver.Conn, f LogFilter) (uint64, error) {
	f = NormalizeLog(f)
	clauses, args := logWhere(f)

	var n uint64
	if err := conn.QueryRow(ctx,
		"SELECT count()"+logFrom+whereClause(clauses), args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("logs count: %w", err)
	}

	return n, nil
}

/*
 * LogFacets — кто и по какому сервису вообще писал в это окно. Одной
 * группировкой, а не двумя DISTINCT: колонки LowCardinality, пар единицы, и
 * второй поход в ClickHouse ради того же ответа не нужен.
 *
 * Считается по окну, а не по всей таблице: список нод, которые молчат неделю,
 * в фильтре сегодняшнего журнала — это не подсказка, а шум.
 */
func LogFacets(ctx context.Context, conn driver.Conn, f LogFilter) ([]LogFacet, error) {
	f = NormalizeLog(f)

	// Только окно: сузить список тем же фильтром, который он же и наполняет,
	// значит оставить в нём одно выбранное значение.
	clauses, args := logWhere(LogFilter{From: f.From, To: f.To})

	sql := "SELECT writer, service, count()" + logFrom + whereClause(clauses) +
		" GROUP BY writer, service ORDER BY writer, service"

	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("logs facets: %w", err)
	}
	defer rows.Close()

	out := make([]LogFacet, 0, 8)

	for rows.Next() {
		var row LogFacet

		if err := rows.Scan(&row.Writer, &row.Service, &row.Count); err != nil {
			return nil, err
		}

		out = append(out, row)
	}

	return out, rows.Err()
}
