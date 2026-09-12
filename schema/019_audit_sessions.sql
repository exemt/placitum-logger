-- Сессии запроса: секция sessions записи kind=request -- чьи сессии назвали
-- инспекторы (docs/verdict-protocol.md#секция-sessions). Своя калитка отдаёт
-- субъект токена, разбор чужого JWT -- claims, подсмотренная сессия
-- приложения -- логин из списка доверенных; на одном запросе их бывает
-- несколько (две калитки на двух волнах, сессия контура и сессия приложения).
--
-- Параллельные массивы, а не строка JSON, в отличие от actions и rewrite: по
-- сессиям фильтруют -- «все запросы alice за сутки», «что делала эта сессия»
-- -- и has() по массиву отвечает на это без разбора строки на каждой строке
-- таблицы. i-й элемент каждого массива -- одна запись секции; логгер держит
-- длины равными. Префикс sessions_ (не session_): session_* -- итог
-- соединения WebSocket (017), это другая вещь.
--
-- Идентификатор -- не сама кука: у своей сессии sid, у чужой -- хеш. Сырой
-- секрет в журнал не попадает по контракту реплая.
--
-- Пустые массивы -- обычное состояние: на маршруте нет калитки либо клиент
-- пришёл без сессии.
ALTER TABLE waf.audit
    ADD COLUMN IF NOT EXISTS sessions_by       Array(LowCardinality(String)),
    ADD COLUMN IF NOT EXISTS sessions_source   Array(LowCardinality(String)),
    ADD COLUMN IF NOT EXISTS sessions_kind     Array(LowCardinality(String)),
    ADD COLUMN IF NOT EXISTS sessions_user     Array(String),
    ADD COLUMN IF NOT EXISTS sessions_id       Array(String),
    ADD COLUMN IF NOT EXISTS sessions_verified Array(UInt8),
    ADD COLUMN IF NOT EXISTS sessions_issued   Array(UInt32),
    ADD COLUMN IF NOT EXISTS sessions_expires  Array(UInt32),
    ADD COLUMN IF NOT EXISTS sessions_groups   Array(String),
    ADD COLUMN IF NOT EXISTS sessions_passive  Array(UInt8),
    ADD INDEX IF NOT EXISTS idx_sessions_user sessions_user
        TYPE bloom_filter(0.01) GRANULARITY 4;
