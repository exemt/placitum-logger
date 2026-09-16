CREATE DICTIONARY IF NOT EXISTS waf.geo_country
(
    prefix String,
    code   String
)
PRIMARY KEY prefix
SOURCE(POSTGRESQL(
    host '${POSTGRES_HOST}'
    port ${POSTGRES_PORT}
    user '${POSTGRES_USER}'
    password '${POSTGRES_PASSWORD}'
    db '${POSTGRES_DB}'
    query 'select a.address as prefix, c.code as code from ip_country_addresses a join ip_countries c on c.id = a.country_id'
))
LAYOUT(IP_TRIE)
LIFETIME(MIN 600 MAX 900)
