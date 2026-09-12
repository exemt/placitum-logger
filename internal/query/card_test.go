package query

import (
	"testing"

	"github.com/exemt/placitum-logger/internal/model"
)

// Чистый allow инспектора: находок нет, модуль профиль не положил.
// Профиль всё равно должен доехать — он есть на маркерной строке kind=inspector.
func TestCardOfKeepsProfileFromCleanFinding(t *testing.T) {
	card := CardOf(Event{
		Node:       "edge-01",
		Ray:        "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
		Phase:      "request",
		By:         model.SelfKey,
		Inspectors: []string{"ip", "modsec"},
		InspectorsVerdict: map[string]string{
			model.SelfKey: "deny",
			"ip":          "allow",
			"modsec":      "score",
		},
		InspectorsScore: map[string]int32{
			"modsec": 100,
		},
		InspectorsProfile: map[string]string{
			"modsec": "default",
		},
	}, []Finding{
		{Inspector: "ip", Profile: "default", Verdict: "allow", Clean: true, EngineMs: 0.2},
		{
			Inspector: "modsec",
			Profile:   "default",
			Verdict:   "score",
			Code:      "crs-942100",
			Severity:  "high",
			Target:    "args",
			Rule:      "942100",
		},
	})

	got := map[string]string{}
	for _, item := range card.Items {
		got[item.Name] = item.Profile
	}

	if got["ip"] != "default" {
		t.Fatalf("ip profile: %q (clean finding must fill the gap)", got["ip"])
	}

	if got["modsec"] != "default" {
		t.Fatalf("modsec profile: %q", got["modsec"])
	}
}

// Слот модуля выигрывает: инспектор мог откатиться на default, а звали другим.
func TestCardOfPrefersSpineProfile(t *testing.T) {
	card := CardOf(Event{
		Inspectors:        []string{"ip"},
		InspectorsVerdict: map[string]string{"ip": "allow"},
		InspectorsProfile: map[string]string{"ip": "admin"},
	}, []Finding{
		{Inspector: "ip", Profile: "default", Verdict: "allow", Clean: true},
	})

	if card.Items[0].Profile != "admin" {
		t.Fatalf("profile: %q", card.Items[0].Profile)
	}
}

/*
 * Склейка просьб с исходами. Модуль перечисляет живые в kind=request, получатель
 * называет исход в своём kind=inspector, и вопрос "ip просил капчу, капчи не
 * было" читается только по обоим сразу.
 */
func TestCardOfJoinsActionOutcomes(t *testing.T) {
	const live = `[
		{"from":"ip","to":"captcha","do":"challenge","apply":"request",
		 "code":"IP_GREYLIST","phase":"request","passive":false},
		{"from":"modsec","do":"note","apply":"asn","code":"MODSEC_SQLI",
		 "value":5,"phase":"request","passive":false},
		{"from":"repu","to":"captcha","do":"skip","apply":"request",
		 "code":"REPU_GOOD","phase":"request","passive":true}
	]`

	card := CardOf(Event{
		Node:    "edge-01",
		Ray:     "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e11",
		Phase:   "request",
		Actions: live,
	}, []Finding{
		{
			Inspector: "captcha",
			Verdict:   "redirect",
			Engine: []byte(`{"actions":[
				{"from":"ip","do":"challenge","apply":"request",
				 "code":"IP_GREYLIST","outcome":"applied"},
				{"from":"modsec","do":"note","apply":"asn",
				 "code":"MODSEC_SQLI","outcome":"applied","took":3}
			]}`),
		},
	})

	if len(card.Actions) != 3 {
		t.Fatalf("actions: %d, want 3 (a request nobody answered still stands)", len(card.Actions))
	}

	first := card.Actions[0]
	if first.To != "captcha" || len(first.Outcomes) != 1 {
		t.Fatalf("challenge: to=%q outcomes=%v", first.To, first.Outcomes)
	}

	if first.Outcomes[0].Inspector != "captcha" || first.Outcomes[0].Outcome != "applied" {
		t.Fatalf("challenge outcome: %+v", first.Outcomes[0])
	}

	second := card.Actions[1]
	if len(second.Outcomes) != 1 || second.Outcomes[0].Outcome != "applied" {
		t.Fatalf("note outcome: %+v", second.Outcomes)
	}

	if second.Outcomes[0].Took == nil || *second.Outcomes[0].Took != 3 {
		t.Fatalf("note took: %v", second.Outcomes[0].Took)
	}

	// Пассивный отправитель: в prior записи не было, значит исхода нет и быть
	// не может. Строка всё равно есть -- ради неё пассивные сюда и пишутся.
	third := card.Actions[2]
	if !third.Passive || len(third.Outcomes) != 0 {
		t.Fatalf("passive action: passive=%v outcomes=%v", third.Passive, third.Outcomes)
	}
}

// Секции нет -- поля нет. Пустой массив в карточке читался бы как "просьбы были
// и все потерялись".
func TestCardOfWithoutActions(t *testing.T) {
	card := CardOf(Event{Node: "edge-01", Ray: "r", Phase: "request"}, nil)

	if card.Actions != nil {
		t.Fatalf("actions: %v, want nil", card.Actions)
	}
}

/*
 * Секции правки раскладываются по участникам. Заказать её могут несколько
 * инспекторов, поднимает модуль ровно один объект -- у остальных applied=false
 * вместе с группами, и это «что было бы применено», а не пропуск.
 */
func TestCardOfRewrite(t *testing.T) {
	ev := Event{
		Node:       "edge-01",
		Ray:        "r",
		Phase:      "response",
		Inspectors: []string{"rewrite", "rewrite-obs"},
		InspectorsVerdict: map[string]string{
			"rewrite":     "allow",
			"rewrite-obs": "allow",
		},
		Rewrite: `{"rewrite":{"applied":true,"size":128,"groups":["mask"]},` +
			`"rewrite-obs":{"applied":false,"groups":["mask"]}}`,
	}

	card := CardOf(ev, nil)

	first := card.Items[0]
	if first.Rewrite == nil || !first.Rewrite.Applied {
		t.Fatalf("applied: %+v", first.Rewrite)
	}

	if first.Rewrite.Size == nil || *first.Rewrite.Size != 128 {
		t.Fatalf("size: %+v", first.Rewrite.Size)
	}

	second := card.Items[1]
	if second.Rewrite == nil || second.Rewrite.Applied {
		t.Fatalf("observer applied: %+v", second.Rewrite)
	}

	if len(second.Rewrite.Groups) != 1 || second.Rewrite.Groups[0] != "mask" {
		t.Fatalf("observer groups: %+v", second.Rewrite)
	}
}

// Правки не было -- поля у участника нет. Кривая строка колонки карточку не
// роняет: остальная запись от этого не портится.
func TestCardOfRewriteAbsentOrBroken(t *testing.T) {
	for _, raw := range []string{"", "{", `{"rewrite": 5}`} {
		card := CardOf(Event{
			Node:              "edge-01",
			Ray:               "r",
			Phase:             "response",
			Inspectors:        []string{"rewrite"},
			InspectorsVerdict: map[string]string{"rewrite": "allow"},
			Rewrite:           raw,
		}, nil)

		if card.Items[0].Rewrite != nil {
			t.Fatalf("%q: rewrite %+v, want nil", raw, card.Items[0].Rewrite)
		}
	}
}
