/*
 * Вид сообщения в потоке waf.audit.>. Читается раньше самого сообщения: у
 * якоря и детали есть одноимённые поля разной формы (score у якоря — объект с
 * порогом, у детали — заявка числом), и разбор чужого конверта целиком дал бы
 * ошибку разбора там, где на деле просто не тот вид.
 */

package model

import "encoding/json"

const (
	// Якорь: единственное сообщение, из которого известно, что за запрос был.
	KindRequest = "request"
	// Деталь: что сработало внутри движка одного инспектора.
	KindInspector = "inspector"
	/*
	 * Пачка: несколько записей одним сообщением. Писатель складывает в неё
	 * ровно те байты, которые уехали бы отдельными сообщениями, поэтому
	 * разбор элемента -- это разбор обычной записи, и новых видов внутри
	 * пачки не бывает.
	 */
	KindBatch = "batch"
)

type envelope struct {
	Kind string `json:"kind"`
}

// batch — конверт пачки. Элементы держатся сырыми: их вид читается тем же
// KindOf, что и у одиночного сообщения.
type batch struct {
	Items []json.RawMessage `json:"items"`
}

// Batch разбирает пачку на записи. Второе значение — это вообще пачка;
// сообщение другого вида возвращает false, а не пустой список.
func Batch(payload []byte) ([]json.RawMessage, bool) {
	if KindOf(payload) != KindBatch {
		return nil, false
	}

	var b batch

	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, false
	}

	return b.Items, true
}

// KindOf возвращает kind сообщения. Пустая строка — конверта нет или он не
// разбирается; такое сообщение в склейку не идёт.
func KindOf(payload []byte) string {
	var env envelope

	if err := json.Unmarshal(payload, &env); err != nil {
		return ""
	}

	return env.Kind
}
