-- Позвоночник: одна строка на (node, ray, phase). Форма записи — схема модуля,
-- docs/messages/agent.schema.ts. Две фазы одного HTTP-запроса — две строки,
-- поэтому phase в ключе.
--
-- Колонка by названа verdict_by: BY — ключевое слово SQL, и цитировать его в
-- каждом запросе дороже, чем один раз назвать колонку иначе.
--
-- Локаторы обменника лежат строками JSON: их форма задана драйвером хранилища и
-- меняется вместе с ним, а фильтровать по ним никто не будет — по ключу из
-- локатора достают тело, когда запись уже нашли.
--
-- Отличие от 005: rev, completeness и inspectors_missing. Детали находок
-- приезжают отдельными сообщениями (kind=inspector) и своей доставкой не
-- связаны с якорем, поэтому у записи появилась вторая ось полноты — доехали ли
-- они, и от кого не доехали.

CREATE TABLE IF NOT EXISTS waf.audit
(
    ts    DateTime64(3),
    node  LowCardinality(String),
    ray   String,
    phase LowCardinality(String),

    -- Редакция: опоздавшая деталь не переписывает строку на месте, а даёт ещё
    -- одну вставку с rev+1.
    rev UInt32,

    -- кто пришёл и на какой фронт попал
    client_ip   IPv6,
    client_port UInt16,
    server_ip   IPv6,
    server_port UInt16,
    tls_version LowCardinality(String),
    tls_sni     String,

    -- запрос: длины вместо содержимого, аномалия видна и без него
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

    -- какая конфигурация сработала
    server_name LowCardinality(String),
    location    LowCardinality(String),

    -- что сделали, почему, кто
    verdict    LowCardinality(String),
    code       LowCardinality(String),
    verdict_by LowCardinality(String),

    score   Int32,
    deny_at Int32,
    shadow  Int32,

    waf_latency_us UInt32,

    -- участники фазы. Массив остаётся рядом с картами: has(inspectors, 'modsec')
    -- дешевле mapKeys, а спрашивают именно так.
    inspectors            Array(LowCardinality(String)),
    inspectors_verdict    Map(LowCardinality(String), LowCardinality(String)),
    inspectors_state      Map(LowCardinality(String), LowCardinality(String)),
    inspectors_score      Map(LowCardinality(String), Int32),
    inspectors_weighted   Map(LowCardinality(String), Int32),
    inspectors_latency_ms Map(LowCardinality(String), Float32),
    inspectors_role       Map(LowCardinality(String), LowCardinality(String)),
    inspectors_profile    Map(LowCardinality(String), LowCardinality(String)),

    -- Доехали ли детали находок: complete — на каждого званого инспектора есть
    -- строки в waf.audit_finding, partial — окно склейки вышло раньше.
    --
    -- Это не то же, что inspectors_state. Там ответ на "ответил ли инспектор
    -- волне" — его знает модуль. Здесь — доставка самого аудита: инспектор мог
    -- ответить deny в срок, а событие с находками потерять по дороге на шину.
    completeness       LowCardinality(String),
    inspectors_missing Array(LowCardinality(String)),

    -- поля запроса, выбранные оператором через waf_var: страна, ASN, UA
    vars Map(LowCardinality(String), String),

    -- где лежит то, что в датаграмму не влезло
    store_headers String,
    store_args    String,
    store_body    String
)
ENGINE = ReplacingMergeTree(rev)
PARTITION BY toDate(ts)
ORDER BY (node, ray, phase)
TTL toDate(ts) + INTERVAL 90 DAY DELETE
