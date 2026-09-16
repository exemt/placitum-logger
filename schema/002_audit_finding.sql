CREATE TABLE IF NOT EXISTS waf.audit_finding
(
    ts    DateTime64(3),
    node  LowCardinality(String),
    ray   String,
    phase LowCardinality(String),
    rev   UInt32,

    inspector LowCardinality(String),
    profile   LowCardinality(String),
    verdict   LowCardinality(String),
    score     Int32,
    engine_ms Float32,

    finding_idx UInt16,
    code        LowCardinality(String),
    severity    LowCardinality(String),
    target      String,
    rule        LowCardinality(String),
    offset      Int64,
    length      Int64,
    confidence  Float32,
    evidence    String,
    message     String,
    tags        Array(LowCardinality(String)),
    engine      String,

    frame_direction LowCardinality(String),
    frame_seq       UInt64,

    INDEX idx_rule rule TYPE bloom_filter GRANULARITY 4,
    INDEX idx_code code TYPE bloom_filter GRANULARITY 4,
    INDEX idx_ray  ray  TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_tags tags TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(rev)
PARTITION BY toDate(ts)
ORDER BY (ts, node, ray, phase, inspector, finding_idx, frame_direction, frame_seq)
TTL toDate(ts) + INTERVAL 90 DAY DELETE
