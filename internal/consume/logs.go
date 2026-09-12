/*
 * Durable pull на waf.log.>: строки access_log и error_log, снятые агентом с
 * сокета ноды. Одно сообщение — пачка строк одной ноды.
 *
 * Свой поток и свой consumer, а не ветка в разборе WAF_AUDIT. Причина не в
 * форме сообщения, а в темпе: access-лог на порядок чаще аудита, и общий
 * consumer означал бы, что всплеск журнала задерживает разбор инцидентов.
 *
 * Ack — после успешной вставки пачки, как и у аудита. Разница в цене повтора:
 * у waf.log нет ключа дедупа, и повторно доставленная пачка ляжет в таблицу
 * второй раз. Это сознательный размен -- см. schema/013_log.sql.
 *
 * Подписка ждёт поток, а не падает без него. Поток заводит писатель (агент
 * ноды), и на контуре, где нода ещё не поднялась, логгер обязан продолжать
 * разбирать аудит, а не перезапускаться по кругу.
 */

package consume

import (
	"context"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-logger/internal/model"
	"github.com/exemt/placitum-logger/internal/sink"
)

const (
	LogStream  = "WAF_LOG"
	LogDurable = "logger-log-v1"
	LogSubject = "waf.log.>"

	// Пачек за выборку меньше, чем сообщений аудита: в каждой уже до пятисот
	// строк, и сотня пачек — это десятки тысяч строк на одну вставку.
	LogBatch = 100

	logWait = 2 * time.Second

	/*
	 * Вставка копится между выборками до LogInsertEvery либо до LogInsertRows
	 * строк. Выборка сама по себе -- то, что накопилось за MaxWait (200 мс), и
	 * в тишине это одна пачка одного сервиса: вставлять её сразу значило
	 * четыре-пять INSERT в секунду по одной строке, часть на каждую и
	 * непрерывные слияния в фоне. На стенде 12.09 это держало ClickHouse на
	 * половине ядра без единого запроса.
	 */
	LogInsertEvery = 2 * time.Second
	LogInsertRows  = 20000
)

func RunLogs(ctx context.Context, nc *nats.Conn, conn driver.Conn, stats *Stats,
	log *slog.Logger) error {

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	sub, err := awaitStream(ctx, js, log)
	if err != nil {
		return err
	}

	log.Info("consuming logs",
		"stream", LogStream,
		"durable", LogDurable,
		"subject", LogSubject,
	)

	var (
		acc  logsBatch
		last = time.Now()
	)

	for {
		if ctx.Err() != nil {
			flushLogs(ctx, conn, acc, stats, log)

			return ctx.Err()
		}

		msgs, err := sub.Fetch(LogBatch, nats.MaxWait(MaxWait))
		if err != nil && err != nats.ErrTimeout {
			flushLogs(ctx, conn, acc, stats, log)

			return err
		}

		b := takeLogs(msgs, stats, log)
		acc.rows = append(acc.rows, b.rows...)
		acc.msgs = append(acc.msgs, b.msgs...)

		/*
		 * Сообщения шины держатся неподтверждёнными до вставки: срок
		 * подтверждения у потока много больше LogInsertEvery, а повтор пачки
		 * после сбоя вставки -- ровно то, что нужно.
		 */
		if len(acc.rows) >= LogInsertRows || time.Since(last) >= LogInsertEvery {
			flushLogs(ctx, conn, acc, stats, log)
			acc = logsBatch{}
			last = time.Now()
		}
	}
}

/*
 * awaitStream ждёт, пока поток заведёт писатель. Ошибка подписки здесь -- это
 * почти всегда "потока ещё нет", и единственный разумный ответ на неё --
 * подождать: логи появятся тогда же, когда появится нода, которая их пишет.
 */
func awaitStream(ctx context.Context, js nats.JetStreamContext,
	log *slog.Logger) (*nats.Subscription, error) {

	said := false

	for {
		sub, err := js.PullSubscribe(LogSubject, LogDurable,
			nats.BindStream(LogStream),
			nats.ManualAck(),
			nats.AckWait(AckWait),
		)
		if err == nil {
			return sub, nil
		}

		if !said {
			log.Warn("log stream not ready", "stream", LogStream, "error", err.Error())
			said = true
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(logWait):
		}
	}
}

type logsBatch struct {
	rows []model.LogRow
	msgs []*nats.Msg
}

func takeLogs(msgs []*nats.Msg, stats *Stats, log *slog.Logger) logsBatch {
	b := logsBatch{msgs: make([]*nats.Msg, 0, len(msgs))}

	for _, m := range msgs {
		start := time.Now()
		rows, err := model.FromLog(m.Data)

		if stats != nil {
			stats.Consume.Add(uint64(len(m.Data)), 0, err != nil, time.Since(start))
		}

		if err != nil {
			log.Warn("skip bad log payload", "error", err.Error(), "subject", m.Subject)
		}

		// Пачка без строк: чужой вид или пустой список. Подтверждаем сразу --
		// иначе шина будет доставлять её вечно.
		if len(rows) == 0 {
			_ = m.Ack()

			continue
		}

		b.rows = append(b.rows, rows...)
		b.msgs = append(b.msgs, m)
	}

	return b
}

func flushLogs(ctx context.Context, conn driver.Conn, b logsBatch, stats *Stats,
	log *slog.Logger) {

	if len(b.msgs) == 0 {
		return
	}

	start := time.Now()
	err := sink.InsertLogs(ctx, conn, b.rows)
	elapsed := time.Since(start)

	if err != nil {
		log.Error("log flush failed", "error", err.Error(), "lines", len(b.rows))

		if stats != nil {
			stats.Insert.AddN(len(b.rows), 0, 0, true, elapsed)
		}

		for _, m := range b.msgs {
			_ = m.Nak()
		}

		return
	}

	if stats != nil {
		stats.Insert.AddN(len(b.rows), 0, 0, false, elapsed)
	}

	for _, m := range b.msgs {
		if err := m.Ack(); err != nil {
			log.Warn("log ack failed", "error", err.Error())
		}
	}

	stats.Add(len(b.rows))

	// Ход работы, а не событие -- debug. И только stdout: разбору WAF_LOG
	// логгер отдаёт Quiet (cmd/logger), иначе эта строка сама становилась бы
	// следующей партией журнала.
	log.Debug("inserted logs", "lines", len(b.rows), "batches", len(b.msgs))
}
