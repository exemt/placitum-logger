/*
 * Поиск по находкам инспекторов. Отдельно от позвоночника: вопросы к нему
 * другие — не "какие запросы прилетели с этого адреса", а "где сработало
 * правило 913100" и "что нашли в этом запросе".
 *
 * JOIN с waf.audit здесь нет намеренно. Профиль, вердикт и счёт инспектора
 * повторены на каждой строке находки при записи, поэтому поиск по правилу
 * читает одну таблицу. Контекст запроса подтягивается на чтении, отдельным
 * запросом карточки, и только когда карточку открыли.
 */

package query

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const findingCols = `ts, node, ray, phase, rev,
	inspector, profile, verdict, score, engine_ms,
	finding_idx, code, severity, target, rule,
	offset, length, confidence, evidence,
	engine,
	frame_direction, frame_seq`

/*
 * Счёт и карточка -- с FINAL: до слияния кусков повторно доставленная находка
 * лежит в таблице дважды. Список -- без него, по той же причине, что список
 * позвоночника (query.go, fromRaw): под FINAL чтение по порядку ключа
 * выключено, и «последние 50» читали бы всё окно. Дубли на странице снимает
 * scanFindings.
 */
const (
	findingFromFinal = " FROM waf.audit_finding FINAL"
	findingFrom      = " FROM waf.audit_finding"
)

// Ключ таблицы задом наперёд -- ради чтения с хвоста; порядок полный.
const findingOrder = " ORDER BY ts DESC, node DESC, ray DESC, phase DESC," +
	" inspector DESC, finding_idx DESC, frame_direction DESC, frame_seq DESC"

type FindingFilter struct {
	From time.Time
	To   time.Time

	Node  string
	Ray   string
	Phase string

	Inspector string
	Profile   string
	Verdict   string

	Rule     string
	Code     string
	Severity string

	Limit  int
	Offset int
}

type Finding struct {
	TS    time.Time `json:"ts"`
	Node  string    `json:"node"`
	Ray   string    `json:"ray"`
	Phase string    `json:"phase"`
	Rev   uint32    `json:"rev,omitempty"`

	Inspector string  `json:"inspector"`
	Profile   string  `json:"profile,omitempty"`
	Verdict   string  `json:"verdict"`
	Score     int32   `json:"score,omitempty"`
	EngineMs  float32 `json:"engine_ms,omitempty"`

	Index      uint16  `json:"index"`
	Code       string  `json:"code,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	Target     string  `json:"target,omitempty"`
	Rule       string  `json:"rule,omitempty"`
	Offset     int64   `json:"offset,omitempty"`
	Length     int64   `json:"length,omitempty"`
	Confidence float32 `json:"confidence,omitempty"`
	Evidence   string  `json:"evidence,omitempty"`

	// Своё движка отдаётся разобранным: клиенту нужен объект, а не текст JSON
	// в поле. Пустая строка — движок ничего своего не прислал.
	Engine json.RawMessage `json:"engine,omitempty"`

	// Адрес кадра внутри соединения; у находок других фаз пусто.
	FrameDirection string `json:"frame_direction,omitempty"`
	FrameSeq       uint64 `json:"frame_seq,omitempty"`

	// Инспектор отработал и не нашёл ничего. Отличается от отсутствия строк:
	// там инспектора не звали вовсе.
	Clean bool `json:"clean,omitempty"`
}

func NormalizeFinding(f FindingFilter) FindingFilter {
	if f.Limit <= 0 {
		f.Limit = 50
	}

	if f.Limit > 200 {
		f.Limit = 200
	}

	if f.Offset < 0 {
		f.Offset = 0
	}

	switch f.Verdict {
	case "allow", "score", "deny", "redirect", "":
	default:
		f.Verdict = ""
	}

	switch f.Severity {
	case "info", "low", "medium", "high", "critical", "":
	default:
		f.Severity = ""
	}

	switch f.Phase {
	case "request", "response", "frame", "session", "":
	default:
		f.Phase = ""
	}

	// Точечный поиск по ray сутками не ограничивают: по ссылке из тикета ищут
	// вчерашний инцидент.
	if f.Ray == "" {
		if f.To.IsZero() {
			f.To = time.Now().UTC()
		}

		if f.From.IsZero() {
			f.From = f.To.Add(-24 * time.Hour)
		}
	}

	return f
}

func ListFindings(ctx context.Context, conn driver.Conn, f FindingFilter) ([]Finding, error) {
	sql, args := buildFindings(NormalizeFinding(f))

	return scanFindings(ctx, conn, sql, args)
}

func CountFindings(ctx context.Context, conn driver.Conn, f FindingFilter) (uint64, error) {
	sql, args := buildFindingCount(NormalizeFinding(f))

	var n uint64
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count findings: %w", err)
	}

	return n, nil
}

func buildFindings(f FindingFilter) (string, []any) {
	clauses, args := whereFinding(f)

	sql := "SELECT " + findingCols + findingFrom + whereClause(clauses) +
		findingOrder + " LIMIT @limit OFFSET @offset"

	args = append(args,
		clickhouse.Named("limit", f.Limit),
		clickhouse.Named("offset", f.Offset),
	)

	return sql, args
}

func buildFindingCount(f FindingFilter) (string, []any) {
	clauses, args := whereFinding(f)

	return "SELECT count()" + findingFromFinal + whereClause(clauses), args
}

/*
 * FindingsByRay — карточка инцидента: всё, что нашли инспекторы в одном
 * запросе. Порядок — по инспектору и позиции находки, а не по времени: в
 * карточке читают состав, а не хронологию, и волна всё равно шла параллельно.
 */
func FindingsByRay(ctx context.Context, conn driver.Conn, node, ray string) ([]Finding, error) {
	return findingsOf(ctx, conn, node, ray, "", 0)
}

/*
 * FindingsByFrame -- находки одного кадра. У соединения под одним ray сотни
 * кадров, и карточка кадра берёт только свои: по стороне и номеру.
 */
func FindingsByFrame(ctx context.Context, conn driver.Conn, node, ray, dir string, seq uint64) ([]Finding, error) {
	return findingsOf(ctx, conn, node, ray, dir, seq)
}

func findingsOf(ctx context.Context, conn driver.Conn, node, ray, dir string, seq uint64) ([]Finding, error) {
	if ray == "" {
		return nil, nil
	}

	// FINAL: находок под ray единицы, а bloom по ray под FINAL включён
	// (ch.go), так что цена -- три гранулы, а не окно.
	sql := "SELECT " + findingCols + findingFromFinal +
		" WHERE ray = @ray"
	args := []any{clickhouse.Named("ray", ray)}

	if node != "" {
		sql += " AND node = @node"
		args = append(args, clickhouse.Named("node", node))
	}

	if dir != "" {
		sql += " AND frame_direction = @dir AND frame_seq = @seq"
		args = append(args, clickhouse.Named("dir", dir), clickhouse.Named("seq", seq))
	}

	sql += " ORDER BY phase, frame_direction, frame_seq, inspector, finding_idx LIMIT @limit"
	args = append(args, clickhouse.Named("limit", maxCardFindings))

	return scanFindings(ctx, conn, sql, args)
}

// Потолок на карточку: волна из десятка инспекторов с сотнями срабатываний
// правил — это уже не карточка, а выгрузка, и грузить её в браузер незачем.
const maxCardFindings = 1000

func whereFinding(f FindingFilter) (clauses []string, args []any) {
	add := func(clause, name string, v any) {
		clauses = append(clauses, clause)
		args = append(args, clickhouse.Named(name, v))
	}

	if f.Ray != "" {
		add("ray = @ray", "ray", f.Ray)
	} else {
		add("ts >= @from", "from", f.From)
		add("ts <= @to", "to", f.To)
	}

	if f.Node != "" {
		add("node = @node", "node", f.Node)
	}

	if f.Phase != "" {
		add("phase = @phase", "phase", f.Phase)
	}

	if f.Inspector != "" {
		add("inspector = @inspector", "inspector", f.Inspector)
	}

	if f.Profile != "" {
		add("profile = @profile", "profile", f.Profile)
	}

	if f.Verdict != "" {
		add("verdict = @verdict", "verdict", f.Verdict)
	}

	if f.Rule != "" {
		add("rule = @rule", "rule", f.Rule)
	}

	if f.Code != "" {
		add("code = @code", "code", f.Code)
	}

	if f.Severity != "" {
		add("severity = @severity", "severity", f.Severity)
	}

	return clauses, args
}

func whereClause(clauses []string) string {
	if len(clauses) == 0 {
		return ""
	}

	return " WHERE " + strings.Join(clauses, " AND ")
}

func scanFindings(ctx context.Context, conn driver.Conn, sql string, args []any) ([]Finding, error) {
	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	out := make([]Finding, 0, 32)

	/*
	 * Дубль до слияния -- та же строка байт в байт; снимается по ключу
	 * таблицы, как на странице позвоночника (dedup). Под FINAL дублей нет,
	 * и проверка ничего не находит.
	 */
	type key struct {
		node, ray, phase, inspector, dir string
		idx                              uint16
		seq                              uint64
	}

	seen := make(map[key]struct{}, 32)

	for rows.Next() {
		var (
			item   Finding
			engine string
		)

		if err := rows.Scan(
			&item.TS,
			&item.Node,
			&item.Ray,
			&item.Phase,
			&item.Rev,

			&item.Inspector,
			&item.Profile,
			&item.Verdict,
			&item.Score,
			&item.EngineMs,

			&item.Index,
			&item.Code,
			&item.Severity,
			&item.Target,
			&item.Rule,

			&item.Offset,
			&item.Length,
			&item.Confidence,
			&item.Evidence,

			&engine,

			&item.FrameDirection,
			&item.FrameSeq,
		); err != nil {
			return nil, err
		}

		item.TS = item.TS.UTC()
		item.Clean = item.Code == "" && item.Rule == ""

		if engine != "" {
			item.Engine = json.RawMessage(engine)
		}

		k := key{item.Node, item.Ray, item.Phase, item.Inspector,
			item.FrameDirection, item.Index, item.FrameSeq}
		if _, dup := seen[k]; dup {
			continue
		}

		seen[k] = struct{}{}
		out = append(out, item)
	}

	return out, rows.Err()
}
