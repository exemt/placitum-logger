CREATE TABLE IF NOT EXISTS waf.audit
(
    ts    DateTime64(3),
    node  LowCardinality(String),
    ray   String,
    phase LowCardinality(String),
    rev   UInt32,

    client_ip   IPv6,
    client_port UInt16,
    server_ip   IPv6,
    server_port UInt16,
    tls_version LowCardinality(String),
    tls_sni     String,

    method        LowCardinality(String),
    scheme        LowCardinality(String),
    host          String,
    uri           String,
    http_version  LowCardinality(String),
    args_size     UInt32,
    headers_size  UInt32,
    headers_count UInt16,
    body_size     UInt64,
    content_type  LowCardinality(String),
    status        UInt16,
    upstream_status UInt16,

    server_name LowCardinality(String),
    location    LowCardinality(String),
    location_id LowCardinality(String),

    verdict    LowCardinality(String),
    code       LowCardinality(String),
    verdict_by LowCardinality(String),

    score   Int32,
    deny_at Int32,
    shadow  Int32,

    waf_latency_us UInt32,

    inspectors            Array(LowCardinality(String)),
    inspectors_verdict    Map(LowCardinality(String), LowCardinality(String)),
    inspectors_state      Map(LowCardinality(String), LowCardinality(String)),
    inspectors_score      Map(LowCardinality(String), Int32),
    inspectors_latency_ms Map(LowCardinality(String), Float32),
    inspectors_role       Map(LowCardinality(String), LowCardinality(String)),
    inspectors_profile    Map(LowCardinality(String), LowCardinality(String)),

    vars Map(LowCardinality(String), String),

    store_headers String,
    store_args    String,
    store_body    String,

    headers_preview Map(LowCardinality(String), String),
    args_preview    Map(LowCardinality(String), String),
    body_preview    String,
    headers_preview_truncated Array(LowCardinality(String)),
    args_preview_truncated    Array(LowCardinality(String)),
    headers_preview_dropped   UInt16,
    args_preview_dropped      UInt16,

    actions String,
    rewrite String,

    frame_direction         LowCardinality(String),
    frame_seq               UInt64,
    frame_opcode            LowCardinality(String),
    frame_size              UInt32,
    frame_fin               UInt8,
    frame_rewritten         UInt8,
    frame_preview           String,
    frame_preview_truncated UInt8,

    session_frames_c2s   UInt64,
    session_frames_s2c   UInt64,
    session_bytes_c2s    UInt64,
    session_bytes_s2c    UInt64,
    session_denied       UInt32,
    session_rewritten    UInt32,
    session_close_code   UInt16,
    session_close_reason LowCardinality(String),
    session_duration_ms  UInt32,

    sessions_by       Array(LowCardinality(String)),
    sessions_source   Array(LowCardinality(String)),
    sessions_kind     Array(LowCardinality(String)),
    sessions_user     Array(String),
    sessions_id       Array(String),
    sessions_verified Array(UInt8),
    sessions_issued   Array(UInt32),
    sessions_expires  Array(UInt32),
    sessions_groups   Array(String),
    sessions_passive  Array(UInt8),

    markers Array(LowCardinality(String)),

    INDEX idx_body_preview lower(body_preview)
        TYPE ngrambf_v1(3, 8192, 3, 0) GRANULARITY 4,
    INDEX idx_sessions_user sessions_user TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_markers markers TYPE bloom_filter(0.01) GRANULARITY 4,

    INDEX idx_ray ray TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_client_ip client_ip TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_sessions_id sessions_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_uri lower(uri) TYPE ngrambf_v1(3, 8192, 3, 0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(rev)
PARTITION BY toDate(ts)
ORDER BY (ts, node, ray, phase, frame_direction, frame_seq)
TTL toDate(ts) + INTERVAL 90 DAY DELETE
