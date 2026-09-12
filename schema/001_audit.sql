-- Позвоночник: одна строка на (node, rid). Поля — logger/search.md.
-- ray / client_ip / country / asn пока пустые: на якоре их нет.

CREATE TABLE IF NOT EXISTS waf.audit
(
    ts         DateTime64(3),
    node       LowCardinality(String),
    rid        String,
    ray        String,
    client_ip  IPv6,
    country    LowCardinality(String),
    asn        UInt32,
    method     LowCardinality(String),
    host       String,
    uri        String,
    status     UInt16,
    verdict            LowCardinality(String),
    score              Int32,
    inspectors         Array(LowCardinality(String)),
    inspectors_verdict Map(LowCardinality(String), LowCardinality(String)),
    inspectors_score   Map(LowCardinality(String), Int32)
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(ts)
ORDER BY (node, rid)
TTL toDate(ts) + INTERVAL 90 DAY DELETE;
