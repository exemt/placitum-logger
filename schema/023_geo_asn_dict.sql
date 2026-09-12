-- ASN адреса: тот же словарь, что и у страны, по каталогу ip_asns.
-- Почему словарём, а не колонкой -- см. 022_geo_country_dict.sql.
--
-- Номер, а не имя: имя оператора («M247 Europe SRL») меняется вместе с
-- регистратурой, а по группе кликают номером. Имя показывает панель, спросив
-- тот же каталог, из которого собран словарь.
CREATE DICTIONARY IF NOT EXISTS waf.geo_asn
(
    prefix String,
    asn    UInt32
)
PRIMARY KEY prefix
SOURCE(POSTGRESQL(
    host '${POSTGRES_HOST}'
    port ${POSTGRES_PORT}
    user '${POSTGRES_USER}'
    password '${POSTGRES_PASSWORD}'
    db '${POSTGRES_DB}'
    query 'select a.address as prefix, c.asn as asn from ip_asn_addresses a join ip_asns c on c.id = a.asn_id'
))
LAYOUT(IP_TRIE)
LIFETIME(MIN 600 MAX 900)
