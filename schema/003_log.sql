CREATE TABLE IF NOT EXISTS waf.log
(
    ts       DateTime64(3),
    writer   LowCardinality(String),
    service  LowCardinality(String),
    severity LowCardinality(String),
    text     String,

    INDEX idx_text lower(text)
        TYPE ngrambf_v1(3, 8192, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, writer, service)
TTL toDate(ts) + INTERVAL 14 DAY DELETE
