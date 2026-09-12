/*
 * Строки waf.audit_finding. Собираются из kind=inspector — события, которое
 * инспектор публикует после ответа в inbox (docs/messages/inspector-audit.schema.ts).
 *
 * Здесь лежит ровно то, чего нет и не может быть у модуля: что именно
 * сработало внутри движка. Контекст запроса сюда не копируется — он на
 * позвоночнике, склейка по ray.
 *
 * Одна находка — одна строка. Массив в колонке был бы дешевле по месту, но
 * "все события по правилу 913100" тогда требуют ARRAY JOIN на каждый запрос, а
 * спрашивают именно так.
 */

package model

import (
	"encoding/json"
	"time"
)

/*
 * Потолок на находки в одном событии. Порядковый номер уходит в ключ
 * сортировки колонкой UInt16, и переполнение молча склеило бы разные находки в
 * одну строку. Настоящие события в этот предел укладываются с запасом:
 * у CRS на запрос срабатывают десятки правил, не тысячи.
 */
const maxFindings = 1024

type FindingRow struct {
	TS    time.Time
	Node  string
	Ray   string
	Phase string
	Rev   uint32

	Inspector string
	Profile   string
	Verdict   string
	Score     int32
	EngineMS  float32

	// Адрес кадра внутри соединения (phase=frame); у остальных фаз пусто.
	FrameDirection string
	FrameSeq       uint64

	FindingIdx uint16
	Code       string
	Severity   string
	Target     string
	Rule       string
	Offset     int64
	Length     int64
	Confidence float32
	Evidence   string

	Engine string
}

// InspectorEvent — разобранное событие одного инспектора. Ключ вынесен наружу:
// по нему корзина склейки находит запрос, не разбирая строки находок.
type InspectorEvent struct {
	Node      string
	Ray       string
	Phase     string
	Inspector string

	Findings []FindingRow
}

type finding struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"`
	Target     string   `json:"target"`
	Offset     *int64   `json:"offset"`
	Length     *int64   `json:"length"`
	Rule       string   `json:"rule"`
	Confidence *float32 `json:"confidence"`
	Evidence   string   `json:"evidence"`
}

type inspectorEvent struct {
	TS        string `json:"ts"`
	Ray       string `json:"ray"`
	Node      string `json:"node"`
	Phase     string `json:"phase"`
	Inspector string `json:"inspector"`
	Profile   string `json:"profile"`

	Verdict  string  `json:"verdict"`
	Score    *int32  `json:"score"`
	EngineMS float32 `json:"engine_ms"`

	Findings []finding       `json:"findings"`
	Engine   json.RawMessage `json:"engine"`

	// Кадр, о котором событие: без него находки всех кадров соединения
	// легли бы под один ключ.
	Frame *struct {
		Direction string `json:"direction"`
		Seq       uint64 `json:"seq"`
	} `json:"frame"`
}

/*
 * FromInspector разбирает событие в строки находок.
 *
 * ok=false — событие не наше или его нечем склеить. Ключ склейки один: ray.
 * Инспектор, который шлёт только rid, доехать не может — слот воркера
 * переиспользуется, и приклеить такое событие было бы хуже, чем потерять:
 * находка легла бы к чужому запросу.
 */
func FromInspector(payload []byte) (InspectorEvent, bool, error) {
	/*
	 * Вид сообщения читается раньше самого сообщения. Одноимённые поля у
	 * якоря и детали устроены по-разному — score там объект с порогом, здесь
	 * заявка числом, — и попытка разобрать чужой конверт целиком дала бы
	 * ошибку разбора там, где на деле просто не тот вид.
	 */
	if KindOf(payload) != KindInspector {
		return InspectorEvent{}, false, nil
	}

	var ev inspectorEvent

	if err := json.Unmarshal(payload, &ev); err != nil {
		return InspectorEvent{}, false, err
	}

	if ev.Node == "" || ev.Ray == "" || ev.Inspector == "" {
		return InspectorEvent{}, false, nil
	}

	phase := ev.Phase
	if phase == "" {
		phase = "request"
	}

	/*
	 * ts ставит инспектор — это момент завершения инспекции. Своё время логгер
	 * подставляет только когда чужого нет: строка обязана попасть в ту же
	 * партицию, что и якорь, иначе карточка инцидента разъезжается по датам.
	 */
	ts, err := time.Parse(time.RFC3339Nano, ev.TS)
	if err != nil {
		ts = time.Now().UTC()
	}

	out := InspectorEvent{
		Node:      ev.Node,
		Ray:       ev.Ray,
		Phase:     phase,
		Inspector: ev.Inspector,
	}

	head := FindingRow{
		TS:        ts.UTC(),
		Node:      ev.Node,
		Ray:       ev.Ray,
		Phase:     phase,
		Inspector: ev.Inspector,
		Profile:   ev.Profile,
		Verdict:   ev.Verdict,
		EngineMS:  ev.EngineMS,
		Engine:    locator(ev.Engine),
	}

	if ev.Frame != nil {
		head.FrameDirection = ev.Frame.Direction
		head.FrameSeq = ev.Frame.Seq
	}

	if ev.Score != nil {
		head.Score = *ev.Score
	}

	/*
	 * Инспектор отработал и не нашёл ничего — это результат, а не отсутствие
	 * события: без строки "не вызвали" и "вызвали, чисто" снова неразличимы.
	 * Вердикт, счёт и величины движка в такой строке настоящие, пусто только
	 * место находки.
	 */
	if len(ev.Findings) == 0 {
		out.Findings = []FindingRow{head}

		return out, true, nil
	}

	items := ev.Findings
	if len(items) > maxFindings {
		items = items[:maxFindings]
	}

	out.Findings = make([]FindingRow, 0, len(items))

	for i, f := range items {
		row := head
		row.FindingIdx = uint16(i)
		row.Code = f.Code
		row.Severity = f.Severity
		row.Target = f.Target
		row.Rule = f.Rule
		row.Evidence = f.Evidence

		// Длина 0 означает, что движок места не назвал: смещение без длины
		// подсветить нечем, и хранить его отдельно незачем.
		if f.Offset != nil && f.Length != nil {
			row.Offset = *f.Offset
			row.Length = *f.Length
		}

		if f.Confidence != nil {
			row.Confidence = *f.Confidence
		}

		out.Findings = append(out.Findings, row)
	}

	return out, true, nil
}
