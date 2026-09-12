-- Находки: тот же переезд, что у позвоночника в 024, по тем же причинам.
-- Ключ (node, ray, phase, inspector, finding_idx) со случайным ray в голове
-- заставлял поиск по правилу за сутки читать всю таблицу и сливать все её
-- куски под FINAL -- четырнадцать миллионов строк на стенде за секунду с
-- лишним. Со временем впереди счёт за сутки отвечает за десятки миллисекунд,
-- а поиск по правилу -- по bloom-индексу, который под FINAL наконец включён
-- (см. 024 про use_skip_indexes_if_final).
--
-- ts здесь ставит инспектор в момент завершения проверки, и у повторной
-- доставки он тот же -- дедуп по ключу с ts в голове цел. Ключ склейки
-- (node, ray, phase, inspector, finding_idx, frame_direction, frame_seq)
-- остаётся в ключе целиком.
--
-- idx_ray -- карточка: все находки одного запроса, без окна времени.
-- Первичный индекс по ray больше не ведёт, bloom ведёт.

CREATE TABLE IF NOT EXISTS waf.audit_finding_v2
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
    engine      String,

    frame_direction LowCardinality(String),
    frame_seq       UInt64,

    INDEX idx_rule rule TYPE bloom_filter GRANULARITY 4,
    INDEX idx_code code TYPE bloom_filter GRANULARITY 4,
    INDEX idx_ray  ray  TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = ReplacingMergeTree(rev)
PARTITION BY toDate(ts)
ORDER BY (ts, node, ray, phase, inspector, finding_idx, frame_direction, frame_seq)
TTL toDate(ts) + INTERVAL 90 DAY DELETE
