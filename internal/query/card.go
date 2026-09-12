/*
 * Карточка инцидента: кто участвовал в решении и что нашёл.
 *
 * Отдельным ресурсом, а не полем списка. Список отвечает на «какие запросы
 * отсекли» и обязан оставаться узким — карты участников и находки раздували бы
 * каждую строку скана. Разбор участников спрашивают ровно один раз, у одной
 * записи, и только когда её открыли.
 *
 * Склейка позвоночника с находками — на чтении. Позвоночник знает, кого звали,
 * кто промолчал, сколько шёл round-trip и какой вес дал маршрут; всё это знает
 * только модуль. Находки знают, что сработало внутри движка; это знает только
 * инспектор. Ни одна из двух сторон не может рассказать за другую, и сводить их
 * при записи значило бы держать якорь до последней опоздавшей детали.
 */

package query

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/model"
)

/*
 * Participant — один участник фазы. Форма одна и на модуль, и на инспектора:
 * так её пишет модуль (docs/messages/agent.schema.ts), и разбирать запись,
 * заглядывая в её имя, читателю не нужно.
 */
type Participant struct {
	Name string `json:"name"`

	// Итог модуля лежит в той же карте, что ответы инспекторов, под ключом
	// module. Без флага карточка не отличит решение контура от чужого ответа.
	Self bool `json:"self,omitempty"`

	// Его вердикт стал итогом фазы: verdict_by указывает на него.
	Decisive bool `json:"decisive,omitempty"`

	// Ровно одно из двух: участник либо ответил, либо нет.
	Verdict string `json:"verdict,omitempty"`
	State   string `json:"state,omitempty"`

	// Что легло в сумму фазы: заявка при score, сотня у совещательного deny.
	Score int32 `json:"score,omitempty"`

	// Round-trip модуля против времени внутри движка. Расхождение между ними и
	// есть ответ на «инспектор тормозит или шина».
	LatencyMs float32 `json:"latency_ms,omitempty"`
	EngineMs  float32 `json:"engine_ms,omitempty"`

	Role    string `json:"role,omitempty"`
	Profile string `json:"profile,omitempty"`

	// Отработал и не нашёл ничего: инспектор прислал событие без находок.
	// Отличается от «не звали» — у того нет записи участника вовсе.
	Clean bool `json:"clean,omitempty"`

	/*
	 * Правка ответа, если этот участник её заказывал. Здесь она нужна затем
	 * же, зачем модуль её пишет: архив и срез хранят оригинал, а клиент
	 * получил другое, и без пометки расхождение читается порчей данных.
	 */
	Rewrite *Rewrite `json:"rewrite,omitempty"`

	// Находки есть, а в карте участников его нет. Так выглядит деталь,
	// приехавшая к чужому якорю или пережившая его.
	Orphan bool `json:"orphan,omitempty"`

	Findings []Finding `json:"findings,omitempty"`
}

// Card — разбор одной записи по участникам. Итог фазы повторён здесь, а не
// оставлен вызывающему: карточку открывают одним запросом, и «кто решил» без
// «что решили» не читается.
type Card struct {
	TS    time.Time `json:"ts"`
	Node  string    `json:"node"`
	Ray   string    `json:"ray"`
	Phase string    `json:"phase"`

	Verdict string `json:"verdict"`
	Code    string `json:"code,omitempty"`
	By      string `json:"by"`

	Score  int32 `json:"score"`
	DenyAt int32 `json:"deny_at,omitempty"`
	Shadow int32 `json:"shadow,omitempty"`

	Items []Participant `json:"items"`
	Count int           `json:"count"`

	// Кадры WebSocket: секции своих фаз.
	Frame   *FrameInfo   `json:"frame,omitempty"`
	Session *SessionInfo `json:"session,omitempty"`

	/*
	 * Просьбы инспекторов друг к другу и что из них вышло. Секции нет, если
	 * никто ни о чём не просил либо канал на маршруте выключен.
	 */
	Actions []Action `json:"actions,omitempty"`
}

/*
 * CardOf собирает разбор из уже прочитанной записи и её находок. Чистая
 * функция: обе стороны склейки достаются одна другой независимо, и порядок
 * походов в ClickHouse к результату отношения не имеет.
 */
/*
 * Rewrite -- секция правки одного участника.
 *
 * Applied отвечает на вопрос «чей объект в итоге отдали»: заказать правку
 * могут несколько инспекторов, поднимает модуль ровно один объект. У
 * наблюдающего профиля и у проигравшего заказ applied=false -- вместе с
 * groups это и есть «что было бы применено».
 */
type Rewrite struct {
	Applied bool `json:"applied"`
	// Длина подменённого тела. Нет секции тела -- правка была только по
	// заголовкам, и размера у неё не бывает.
	Size   *uint64  `json:"size,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

/*
 * rewritesOf разбирает колонку rewrite -- карту "инспектор -> секция", как её
 * сложил логгер. Разбор здесь по той же причине, что у actions: колонка
 * хранится строкой, потому что по ней не фильтруют.
 *
 * Кривая строка -- не повод ронять карточку: остальная запись от этого не
 * портится, а участник просто останется без пометки.
 */
/*
 * samePhase -- находки той же фазы, что запись: исходы просьб (engine.actions
 * в kind=inspector) читаются только у участников этой фазы, иначе исход
 * запроса приклеился бы к записи ответа того же ray.
 */
func samePhase(phase string, findings []Finding) []Finding {
	if phase == "" {
		return findings
	}

	out := make([]Finding, 0, len(findings))

	for _, item := range findings {
		if item.Phase == "" || item.Phase == phase {
			out = append(out, item)
		}
	}

	return out
}

func rewritesOf(raw string) map[string]Rewrite {
	if raw == "" {
		return nil
	}

	var items map[string]Rewrite

	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil
	}

	return items
}

/*
 * Action -- одна просьба и её судьба. Модуль перечисляет живые в kind=request,
 * исход называет получатель в своём kind=inspector, и склеиваются они здесь:
 * это два разных сообщения, приходящие врозь, и одно без другого отвечает лишь
 * на половину вопроса «ip просил капчу, капчи не было».
 */
type Action struct {
	From string `json:"from,omitempty"`
	// Пусто -- широковещательная: «всем» не имя адресата.
	To    string `json:"to,omitempty"`
	Do    string `json:"do"`
	Apply string `json:"apply,omitempty"`
	Code  string `json:"code,omitempty"`
	Delta *int   `json:"delta,omitempty"`
	Value *int   `json:"value,omitempty"`
	// Метка события у do: mark -- без неё строка «Добавить маркер» в карточке
	// не говорит, что именно помечено.
	Marker string `json:"marker,omitempty"`
	Phase  string `json:"phase,omitempty"`

	/*
	 * Отправитель пассивен -- значит, доставлено не было: записи в prior нет
	 * вовсе. Исходов у такой просьбы не будет ни одного, и это не пробел
	 * склейки, а сам ответ.
	 */
	Passive bool `json:"passive,omitempty"`

	// По записи на каждого, кто о ней отчитался. У широковещательной их
	// столько, сколько получателей её услышало.
	Outcomes []ActionOutcome `json:"outcomes,omitempty"`
}

// ActionOutcome -- что сделал с просьбой один получатель.
type ActionOutcome struct {
	Inspector string   `json:"inspector"`
	Outcome   string   `json:"outcome"`
	Took      *float64 `json:"took,omitempty"`
}

// wireAction -- форма действия на проводе, общая у модуля и у получателя:
// модуль пишет левую половину полей, получатель -- правую.
type wireAction struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	Do      string   `json:"do"`
	Apply   string   `json:"apply"`
	Code    string   `json:"code"`
	Delta   *int     `json:"delta"`
	Value   *int     `json:"value"`
	Marker  string   `json:"marker"`
	Phase   string   `json:"phase"`
	Passive bool     `json:"passive"`
	Outcome string   `json:"outcome"`
	Took    *float64 `json:"took"`
}

// actionKey -- чем одна и та же просьба узнаётся в двух сообщениях. Адресата в
// ключе нет: у широковещательной его не было и у отправителя. Метка в ключе
// есть: две метки одного отправителя с одним поводом -- две разные просьбы.
func actionKey(a wireAction) [5]string {
	return [5]string{a.From, a.Do, a.Apply, a.Code, a.Marker}
}

/*
 * actionsOf -- живые просьбы модуля с приклеенными исходами получателей.
 *
 * Просьба без единого исхода -- законный и самый интересный случай: её никто не
 * услышал либо услышавший смолчал. Она остаётся в списке с пустым Outcomes,
 * потому что именно её приходят разбирать.
 */
func actionsOf(raw string, findings []Finding) []Action {
	if raw == "" {
		return nil
	}

	var live []wireAction

	if err := json.Unmarshal([]byte(raw), &live); err != nil || len(live) == 0 {
		return nil
	}

	said := make(map[[5]string][]ActionOutcome, len(live))

	for _, item := range findings {
		if len(item.Engine) == 0 {
			continue
		}

		var eng struct {
			Actions []wireAction `json:"actions"`
		}

		if err := json.Unmarshal(item.Engine, &eng); err != nil {
			continue
		}

		for _, got := range eng.Actions {
			if got.Outcome == "" {
				continue
			}

			key := actionKey(got)
			said[key] = append(said[key], ActionOutcome{
				Inspector: item.Inspector,
				Outcome:   got.Outcome,
				Took:      got.Took,
			})
		}
	}

	out := make([]Action, 0, len(live))

	for _, a := range live {
		out = append(out, Action{
			From:     a.From,
			To:       a.To,
			Do:       a.Do,
			Apply:    a.Apply,
			Code:     a.Code,
			Delta:    a.Delta,
			Value:    a.Value,
			Marker:   a.Marker,
			Phase:    a.Phase,
			Passive:  a.Passive,
			Outcomes: said[actionKey(a)],
		})
	}

	return out
}

func CardOf(ev Event, findings []Finding) Card {
	card := Card{
		TS:    ev.TS,
		Node:  ev.Node,
		Ray:   ev.Ray,
		Phase: ev.Phase,
		// [] на проводе, не null: у сессии участников нет, и клиент читает длину.
		Items: []Participant{},

		Verdict: ev.Verdict,
		Code:    ev.Code,
		By:      ev.By,

		Score:  ev.Score,
		DenyAt: ev.DenyAt,
		Shadow: ev.Shadow,

		Actions: actionsOf(ev.Actions, samePhase(ev.Phase, findings)),

		Frame:   ev.Frame,
		Session: ev.Session,
	}

	rewrites := rewritesOf(ev.Rewrite)

	byName := make(map[string][]Finding, len(findings))
	engine := make(map[string]float32, len(findings))
	clean := make(map[string]bool, len(findings))
	profiles := make(map[string]string, len(findings))

	for _, item := range findings {
		if item.Phase != "" && ev.Phase != "" && item.Phase != ev.Phase {
			continue
		}

		if item.EngineMs > engine[item.Inspector] {
			engine[item.Inspector] = item.EngineMs
		}

		/*
		 * Профиль живёт и на чистой строке: инспектор пишет его всегда, а
		 * модуль в kind=request поле опускает, когда слот пуст (это default).
		 * Выбросить чистую находку вместе с профилем — у allow без срабатываний
		 * в карточке остаётся голое имя.
		 */
		if item.Profile != "" && profiles[item.Inspector] == "" {
			profiles[item.Inspector] = item.Profile
		}

		/*
		 * Пустая находка — это отметка «звали, чисто», а не находка. В список
		 * она не идёт: там её пришлось бы отличать от настоящей по пустым
		 * полям, и ровно это уже сделано здесь один раз.
		 */
		if item.Clean {
			clean[item.Inspector] = true
			continue
		}

		byName[item.Inspector] = append(byName[item.Inspector], item)
	}

	// Модуль первым, инспекторы следом в том же порядке, в каком их отдаёт
	// позвоночник: он отсортирован при разборе якоря.
	names := make([]string, 0, len(ev.Inspectors)+1)

	if _, ok := ev.InspectorsVerdict[model.SelfKey]; ok {
		names = append(names, model.SelfKey)
	}

	names = append(names, ev.Inspectors...)

	seen := make(map[string]bool, len(names))

	for _, name := range names {
		if seen[name] {
			continue
		}

		seen[name] = true

		card.Items = append(card.Items, Participant{
			Name:     name,
			Self:     name == model.SelfKey,
			Decisive: name == ev.By,

			Verdict: ev.InspectorsVerdict[name],
			State:   ev.InspectorsState[name],

			Score: ev.InspectorsScore[name],

			LatencyMs: ev.InspectorsLatencyMs[name],
			EngineMs:  engine[name],

			Role:    ev.InspectorsRole[name],
			Profile: firstProfile(ev.InspectorsProfile[name], profiles[name]),

			Clean:    clean[name] && len(byName[name]) == 0,
			Findings: byName[name],
			Rewrite:  rewriteOf(rewrites, name),
		})
	}

	/*
	 * Находки без участника. Молча выбросить их нельзя: это либо деталь,
	 * пережившая свой якорь, либо инспектор, которого модуль в карту не
	 * положил, — и то и другое стоит увидеть, а не искать потом в CH руками.
	 */
	for _, name := range sortedKeys(byName) {
		if seen[name] {
			continue
		}

		card.Items = append(card.Items, Participant{
			Name:     name,
			Orphan:   true,
			EngineMs: engine[name],
			Profile:  profiles[name],
			Findings: byName[name],
		})
	}

	card.Count = len(card.Items)

	return card
}

// CardByRay читает обе стороны и склеивает их. Записи нет — карточки нет:
// находки без запроса не карточка, а сирота, и показывать их как инцидент
// значило бы врать о том, чего не было.
func CardByRay(ctx context.Context, conn driver.Conn, node, ray, phase, frame string) (Card, bool, error) {
	ev, ok, err := One(ctx, conn, node, ray, phase, frame)
	if err != nil || !ok {
		return Card{}, false, err
	}

	findings, err := FindingsFor(ctx, conn, ev)
	if err != nil {
		return Card{}, false, err
	}

	return CardOf(ev, findings), true, nil
}

/*
 * FindingsFor -- находки к записи: у кадра только свои (по стороне и
 * номеру), у остальных фаз -- всего ray; фазу отсеет CardOf. Кадры одного
 * соединения к карточке рукопожатия не относятся: у них своя запись.
 */
func FindingsFor(ctx context.Context, conn driver.Conn, ev Event) ([]Finding, error) {
	if ev.Frame != nil {
		return FindingsByFrame(ctx, conn, ev.Node, ev.Ray, ev.Frame.Direction, ev.Frame.Seq)
	}

	// У сессии участников нет: она итог соединения, находки -- у его кадров.
	if ev.Session != nil {
		return nil, nil
	}

	return FindingsByRay(ctx, conn, ev.Node, ev.Ray)
}

func firstProfile(spine, finding string) string {
	if spine != "" {
		return spine
	}

	return finding
}

func sortedKeys(in map[string][]Finding) []string {
	out := make([]string, 0, len(in))

	for name := range in {
		out = append(out, name)
	}

	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}

	return out
}

// rewriteOf -- секция участника, если она была. Копия, а не указатель в карту:
// карточку собирают один раз, но отдавать наружу ссылку внутрь разобранного
// JSON незачем.
func rewriteOf(items map[string]Rewrite, name string) *Rewrite {
	item, ok := items[name]

	if !ok {
		return nil
	}

	return &item
}
