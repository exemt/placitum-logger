package query

import "strings"

/*
 * Страна и ASN адреса.
 *
 * Колонок под них в waf.audit нет: значение знает не модуль, а каталог
 * пространства (`ip_countries`, `ip_asns`) -- тот же, из которого компилируются
 * паки инспектора адреса и отвечает карточка адреса в панели. В ClickHouse он
 * приходит словарём `IP_TRIE` (logger/schema/022, 023), поэтому фильтр и
 * группировка работают и на том, что записано до заливки каталога, а путь
 * записи о гео вовсе не знает.
 *
 * `dictGetOrDefault`, а не `dictGet`: адреса вне каталога -- обычное дело
 * (внутренние сети, свежие префиксы), и пустая строка с нулём здесь значат
 * «каталог не знает», а не ошибку.
 */
const (
	CountryExpr = "dictGetOrDefault('waf.geo_country', 'code', client_ip, '')"
	ASNExpr     = "dictGetOrDefault('waf.geo_asn', 'asn', client_ip, toUInt32(0))"
)

/*
 * Код страны приводится к виду каталога: две буквы в нижнем регистре.
 * Панель показывает их заглавными, и запрос приходит и так и так; всё
 * остальное -- не код, и фильтровать по нему нечего.
 */
func normalizeCountry(raw string) string {
	code := strings.ToLower(strings.TrimSpace(raw))

	if len(code) != 2 {
		return ""
	}

	for _, r := range code {
		if r < 'a' || r > 'z' {
			return ""
		}
	}

	return code
}
