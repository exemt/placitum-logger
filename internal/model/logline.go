/*
 * Пачка строк лога с ноды: сообщение kind=log потока WAF_LOG.
 *
 * Writer стоит на конверте, а не на каждой строке: пачку собирает одна нода, и
 * повторять её имя пятьсот раз на проводе незачем. В таблице он, наоборот, на
 * каждой строке — это её первый фильтр.
 *
 * Время ставит агент в момент приёма датаграммы. Своей отметки у строки нет:
 * шапка syslog не знает ни года, ни зоны, ни долей секунды, а собственное
 * время nginx остаётся внутри текста.
 */

package model

import (
	"encoding/json"
	"strings"
	"time"
)

// KindLog — вид сообщения потока WAF_LOG. Соседствует с KindRequest и
// KindInspector по имени, но не по потоку: у логов свой стрим и свой consumer.
const KindLog = "log"

// maxText — потолок текста строки, тот же, что у агента. Здесь он не режет, а
// защищает: писатель в сокет может оказаться не тем, за кого себя выдаёт.
const maxText = 8 << 10

// LogRow — строка waf.log.
type LogRow struct {
	TS       time.Time
	Writer   string
	Service  string
	Severity string
	Text     string
}

type logLine struct {
	TS       string `json:"ts"`
	Service  string `json:"service"`
	Severity string `json:"severity"`
	Text     string `json:"text"`
}

type logBatch struct {
	Writer string    `json:"writer"`
	Lines  []logLine `json:"lines"`
}

// defaultService — чем подписана строка, у которой сервиса не оказалось.
// Пустое поле в LowCardinality-колонке ничем не хуже, но по нему нельзя
// отфильтровать, а спрашивают именно так.
const defaultService = "nginx"

/*
 * FromLog разбирает пачку в строки. Битая строка внутри пачки пропускается, а
 * не роняет всю пачку: одна испорченная запись не повод потерять четыреста
 * соседних.
 */
func FromLog(payload []byte) ([]LogRow, error) {
	var b logBatch

	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, err
	}

	writer := strings.TrimSpace(b.Writer)
	if writer == "" {
		writer = "unknown"
	}

	out := make([]LogRow, 0, len(b.Lines))

	for _, line := range b.Lines {
		text := line.Text
		if text == "" {
			continue
		}

		if len(text) > maxText {
			text = text[:maxText]
		}

		ts, err := time.Parse(time.RFC3339Nano, line.TS)
		if err != nil {
			ts = time.Now().UTC()
		}

		service := line.Service
		if service == "" {
			service = defaultService
		}

		out = append(out, LogRow{
			TS:       ts.UTC(),
			Writer:   writer,
			Service:  service,
			Severity: line.Severity,
			Text:     text,
		})
	}

	return out, nil
}
