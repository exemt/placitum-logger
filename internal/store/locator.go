/*
 * Локатор обменника: где лежит объект и что о нём известно.
 *
 * Форма — секция store записи аудита, docs/messages/agent.schema.ts. Поля,
 * описывающие содержимое, верны и после переезда в архив, и после удаления
 * объекта: размер и контрольная сумма переживают сам объект, и часто их
 * достаточно тому, кто разбирает инцидент.
 */

package store

import (
	"encoding/json"
	"strings"
	"time"
)

// Kinds — виды объектов обменника в том порядке, в каком их пишет модуль.
var Kinds = []string{"headers", "args", "body"}

type Locator struct {
	/*
	 * Почему содержимого не будет. Модуль ставит oversize, store_error,
	 * store_unconfigured, streaming_not_supported, transform_failed; агент
	 * добавляет expired и archive_error. Размер и контрольная сумма при этом
	 * остаются — они всё ещё верны, и ровно они нужны, когда полезной
	 * нагрузки уже нет.
	 */
	Unavailable string `json:"unavailable,omitempty"`

	Size         int64  `json:"size"`
	DeclaredSize int64  `json:"declared_size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Complete     *bool  `json:"complete,omitempty"`
	Truncated    *bool  `json:"truncated,omitempty"`
	Encoding     string `json:"encoding,omitempty"`

	/*
	 * Адресация. Её нет ровно тогда, когда по ней уже нечего достать: всё, что
	 * маршрут не назвал в waf_archive, модуль удалил сразу после вердикта.
	 *
	 * В записи аудита она всегда архивная: hint относится к горячему обменнику, и
	 * агент выбрасывает его, подменяя локатор. Поэтому здесь его нет.
	 */
	Store  string `json:"store,omitempty"`
	Driver string `json:"driver,omitempty"`
	Key    string `json:"key,omitempty"`

	/*
	 * Unix-время, после которого объекта в архиве не будет: срок называет само
	 * хранилище своим lifecycle-правилом, а агент переносит его в запись. Ноль
	 * значит «срок неизвестен» — правила в бакете нет либо оно не назвалось, —
	 * и это не то же, что истёкший: за неизвестным сроком идут как ни в чём не
	 * бывало.
	 */
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// Addressable — по локатору ещё можно за чем-то прийти.
func (l Locator) Addressable() bool {
	return l.Unavailable == "" && l.Driver != "" && l.Key != ""
}

// Expired — срок объекта известен и уже прошёл.
func (l Locator) Expired(now time.Time) bool {
	return l.ExpiresAt > 0 && now.Unix() >= l.ExpiresAt
}

/*
 * ParseLocator разбирает колонку store_headers / store_args / store_body.
 * Пустая строка — объект не сохраняли вовсе: маршрут его не снимает, класть
 * было нечего либо волна обменника не открывала. Это не ошибка и не отличается
 * от "локатора нет".
 */
func ParseLocator(raw string) (Locator, bool) {
	raw = strings.TrimSpace(raw)

	if raw == "" || raw == "null" {
		return Locator{}, false
	}

	var loc Locator
	if err := json.Unmarshal([]byte(raw), &loc); err != nil {
		return Locator{}, false
	}

	return loc, true
}
