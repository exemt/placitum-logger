package query

import "strings"

const (
	CountryExpr = "dictGetOrDefault('waf.geo_country', 'code', client_ip, '')"
	ASNExpr     = "dictGetOrDefault('waf.geo_asn', 'asn', client_ip, toUInt32(0))"
)

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
