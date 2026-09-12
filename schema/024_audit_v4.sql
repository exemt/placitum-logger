-- Позвоночник получает ключ сортировки, который начинается со времени, и
-- skip-индексы под точечные фильтры. Ключ у MergeTree на месте не меняется
-- (MODIFY ORDER BY умеет только дописывать колонки в хвост), поэтому таблица
-- пересоздаётся -- на этот раз с переносом данных: 024 создаёт новую рядом,
-- 025 меняет их местами, 026 переливает старые строки, 027 сносит старую.
--
-- Почему ts впереди. Ключ (node, ray, phase) был ключом склейки, и только им:
-- ray -- случайный UUID, и по нему строки ложились в куски вразнобой. Каждый
-- вопрос журнала -- окно времени, и на таком ключе он читал все гранулы окна
-- целиком: «последние 50 запросов» стоили столько же, сколько «все запросы за
-- сутки». Хуже того, при случайном ключе куски одной партиции пересекаются по
-- всему диапазону, и FINAL сливал их заново на каждом запросе. С ts впереди
-- куски ложатся встык (вставки идут в порядке времени), FINAL сводит только
-- границы, список читается с хвоста ключа и останавливается на LIMIT, а окно
-- отсекается первичным индексом, а не партицией целиком.
--
-- Дедуп при этом цел. ReplacingMergeTree схлопывает строки с равным ключом,
-- и ts в ключе означает, что дубль обязан нести то же время. Так и есть: ts
-- ставит модуль в момент поступления запроса (у находки -- инспектор), и
-- повторная доставка с шины несёт ту же строку байт в байт. Единственный
-- случай другого ts -- запись без разборного времени, которой логгер ставит
-- своё (model/row.go); такая пара останется двумя строками, и это цена,
-- которой стоит порядок.
--
-- Ключ склейки (node, ray, phase, frame_direction, frame_seq) остаётся в
-- ключе целиком -- после ts. Он по-прежнему единственное, по чему строка
-- обязана быть одна.
--
-- Индексы. Точечные вопросы, которые раньше отвечал первичный ключ или не
-- отвечал никто:
--   ray       -- карточка по ссылке из тикета, без окна времени. Первичный
--                индекс ray больше не ведёт, bloom на каждой грануле -- это
--                читать три гранулы вместо всех.
--   client_ip -- «что делал этот адрес». Bloom работает только на равенстве
--                и IN, поэтому одиночный адрес запрос сравнивает так, а не
--                функцией «в сети» поверх строки (query.go).
--   sessions_id, lower(uri) -- по тем же соображениям, что sessions_user и
--                body_preview: «что делала эта сессия» и «где в пути
--                wp-admin» -- has() и LIKE по редкому значению.
-- Прежние три (body_preview, sessions_user, markers) переезжают как были.
--
-- Skip-индексы под FINAL в 24.8 выключены настройкой use_skip_indexes_if_final
-- -- ClickHouse боится пропустить гранулу с самой свежей версией строки. У
-- нас версий нет (rev всегда 0, дубли одинаковы), поэтому логгер и поиск
-- включают её на соединении (internal/ch/ch.go). Без этого ни один
-- skip-индекс таблицы не работал вовсе.

CREATE TABLE IF NOT EXISTS waf.audit_v4
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
