/*
 * Durable pull на waf.audit.>: и якорь агента (kind=request), и детали
 * инспекторов (kind=inspector). Каждое сообщение самостоятельно: якорь даёт
 * строку в waf.audit, событие инспектора — строки в waf.audit_finding.
 *
 * Друг друга события здесь не ждут. Общий ключ (node, ray, phase) у них есть,
 * но нужен он читателю, а не писателю: карточка инцидента сводит обе стороны
 * на чтении, см. internal/query/card.go. Держать якорь до последней детали
 * значило бы дать логгеру состояние, а с состоянием он не переживает вторую
 * реплику: durable consumer один на всех, и фрагменты одного запроса
 * разъезжаются по процессам, после чего ни один не видит запрос целиком.
 *
 * Ack — после успешной вставки батча, а не после разбора: падение логгера
 * должно означать повтор из JetStream, а не дыру в логе. Повтор безопасен сам
 * по себе — ключ сортировки обеих таблиц совпадает с ключом записи, и
 * ReplacingMergeTree схлопывает повторную доставку в ту же строку.
 */

package consume

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-logger/internal/model"
	"github.com/exemt/placitum-logger/internal/sink"
)

const (
	Stream  = "WAF_AUDIT"
	Durable = "logger-audit-v2"
	Subject = "waf.audit.>"
	Batch   = 500
	MaxWait = 200 * time.Millisecond
	AckWait = 30 * time.Second

	/*
	 * Потолок выборки в байтах. С появлением пачек одно сообщение несёт до
	 * двухсот пятидесяти шести записей, и пятьсот сообщений -- это уже сотни
	 * мегабайт в памяти на одну выборку. Число сообщений при этом снижать
	 * нельзя: писатели переезжают на пачки по одному, и у тех, кто ещё пишет
	 * по записи, выборка осталась бы крошечной.
	 */
	FetchBytes = 16 << 20

	/*
	 * Целевой размер вставки в строках. ClickHouse любит десятки тысяч строк
	 * в партии; пятьсот строк на вставку -- это сотни партов в секунду и
	 * "too many parts" через минуту работы.
	 */
	InsertRows = 20000

	/*
	 * Дольше не копим, даже когда строк мало: на тихом контуре запись обязана
	 * доезжать до журнала за секунды. Заведомо меньше AckWait -- иначе
	 * накопленное успело бы уехать на повтор прямо из-под вставки.
	 */
	InsertEvery = 2 * time.Second

	/*
	 * Глубина конвейера между выборкой и вставкой. Двух выборок в полёте
	 * хватает, чтобы вставка не ждала шину; больше -- это просто память.
	 */
	pipeline = 2
)

func Run(ctx context.Context, nc *nats.Conn, conn driver.Conn, stats *Stats,
	log *slog.Logger) error {

	js, err := nc.JetStream()
	if err != nil {
		return fmt.Errorf("jetstream: %w", err)
	}

	sub, err := js.PullSubscribe(Subject, Durable,
		nats.BindStream(Stream),
		nats.ManualAck(),
		nats.AckWait(AckWait),
	)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	log.Info("consuming",
		"stream", Stream,
		"durable", Durable,
		"subject", Subject,
	)

	/*
	 * Выборка и вставка разнесены по горутинам. В прежнем цикле, пока шла
	 * вставка, с шины не забиралось ничего: пропускная способность равнялась
	 * 1/(выборка + вставка), а не максимуму из них.
	 */
	batches := make(chan batch, pipeline)
	done := make(chan error, 1)

	go func() { done <- insert(ctx, conn, batches, stats, log) }()

	ferr := fetch(ctx, sub, batches, stats, log)

	// Закрытие канала -- сигнал вставке дописать накопленное: в нём строки,
	// сообщения которых ещё не подтверждены.
	close(batches)

	if ierr := <-done; ferr == nil {
		return ierr
	}

	return ferr
}

// fetch забирает с шины и разбирает. Ошибка выборки останавливает обе
// горутины: без шины вставлять нечего.
func fetch(ctx context.Context, sub *nats.Subscription, out chan<- batch,
	stats *Stats, log *slog.Logger) error {

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		msgs, err := sub.Fetch(Batch,
			nats.MaxWait(MaxWait), nats.PullMaxBytes(FetchBytes))
		if err != nil && err != nats.ErrTimeout {
			return fmt.Errorf("fetch: %w", err)
		}

		b := take(msgs, stats, log)
		if len(b.msgs) == 0 {
			continue
		}

		select {
		case out <- b:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

/*
 * insert копит выборки до целевого размера партии и вставляет их разом.
 * Копится именно здесь, а не в выборке: размер выборки задаёт шина (число
 * сообщений и байт), а размер партии -- ClickHouse, и это разные числа.
 */
func insert(ctx context.Context, conn driver.Conn, in <-chan batch, stats *Stats,
	log *slog.Logger) error {

	tick := time.NewTicker(InsertEvery)
	defer tick.Stop()

	var acc batch

	for {
		select {
		case b, ok := <-in:
			if !ok {
				flush(ctx, conn, acc, stats, log)

				return nil
			}

			acc.rows = append(acc.rows, b.rows...)
			acc.findings = append(acc.findings, b.findings...)
			acc.msgs = append(acc.msgs, b.msgs...)

			if len(acc.rows)+len(acc.findings) >= InsertRows {
				flush(ctx, conn, acc, stats, log)
				acc = batch{}
			}

		case <-tick.C:
			flush(ctx, conn, acc, stats, log)
			acc = batch{}
		}
	}
}

// batch — одна выборка с шины: строки на вставку и сообщения, которые эта
// вставка подтверждает. Сообщения держатся до конца вставки, поэтому список
// строк и список сообщений живут вместе.
type batch struct {
	rows     []model.Row
	findings []model.FindingRow
	msgs     []*nats.Msg
}

func take(msgs []*nats.Msg, stats *Stats, log *slog.Logger) batch {
	b := batch{msgs: make([]*nats.Msg, 0, len(msgs))}

	for _, m := range msgs {
		start := time.Now()
		rows, findings, err := parse(m.Data)

		if stats != nil {
			stats.Consume.Add(uint64(len(m.Data)), 0, err != nil, time.Since(start))
		}

		if err != nil {
			log.Warn("skip bad payload", "error", err.Error(), "subject", m.Subject)
		}

		/*
		 * Строк от этого сообщения не будет: чужой вид либо нечем опознать
		 * запрос. Подтверждаем сразу — иначе шина будет доставлять его вечно.
		 */
		if len(rows) == 0 && len(findings) == 0 {
			_ = m.Ack()

			continue
		}

		b.rows = append(b.rows, rows...)
		b.findings = append(b.findings, findings...)
		b.msgs = append(b.msgs, m)
	}

	return b
}

func parse(payload []byte) ([]model.Row, []model.FindingRow, error) {
	switch model.KindOf(payload) {
	// Пустой вид — якорь: агент дописывает kind, но проверять это на каждом
	// сообщении дороже, чем разобрать запись, у которой всё остальное на месте.
	case model.KindRequest, "":
		row, ok, err := model.FromRequest(payload)
		if err != nil || !ok {
			return nil, nil, err
		}

		return []model.Row{row}, nil, nil

	case model.KindInspector:
		ev, ok, err := model.FromInspector(payload)
		if err != nil || !ok {
			return nil, nil, err
		}

		return nil, ev.Findings, nil

	/*
	 * Пачка: писатель сложил в одно сообщение то, что уехало бы десятками.
	 * Элемент разбирается тем же parse -- внутри пачки лежат обычные записи,
	 * и знать о ней должен только этот case.
	 *
	 * Битый элемент не отменяет остальные: пачка -- это транспорт, а не
	 * транзакция, и терять из-за одной записи двести пятьдесят пять было бы
	 * хуже, чем потерять одну.
	 */
	case model.KindBatch:
		items, ok := model.Batch(payload)
		if !ok {
			return nil, nil, nil
		}

		var (
			rows     []model.Row
			findings []model.FindingRow
			first    error
		)

		for _, item := range items {
			r, f, err := parse(item)
			if err != nil && first == nil {
				first = err
			}

			rows = append(rows, r...)
			findings = append(findings, f...)
		}

		return rows, findings, first
	}

	return nil, nil, nil
}

func flush(ctx context.Context, conn driver.Conn, b batch, stats *Stats,
	log *slog.Logger) {

	if len(b.msgs) == 0 {
		return
	}

	start := time.Now()
	err := write(ctx, conn, b.rows, b.findings)
	elapsed := time.Since(start)
	n := len(b.rows) + len(b.findings)

	if err != nil {
		log.Error("flush failed", "error", err.Error(),
			"anchors", len(b.rows), "findings", len(b.findings))

		if stats != nil {
			stats.Insert.AddN(n, 0, 0, true, elapsed)
		}

		// Не подтверждаем: сообщения уедут на повтор и вставятся заново.
		for _, m := range b.msgs {
			_ = m.Nak()
		}

		return
	}

	if stats != nil {
		stats.Insert.AddN(n, 0, 0, false, elapsed)
	}

	for _, m := range b.msgs {
		if err := m.Ack(); err != nil {
			log.Warn("ack failed", "error", err.Error())
		}
	}

	stats.Add(n)

	// Строка на пачку -- не событие, а ход работы: темп вставки и так виден
	// в пульсе, а на info она давала бы журналу контура строку на каждую
	// партию аудита. Отладке -- как раз она.
	log.Debug("inserted", "anchors", len(b.rows), "findings", len(b.findings))
}

func write(ctx context.Context, conn driver.Conn, rows []model.Row, findings []model.FindingRow) error {
	if err := sink.Insert(ctx, conn, rows); err != nil {
		return err
	}

	return sink.InsertFindings(ctx, conn, findings)
}
