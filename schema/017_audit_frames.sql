-- Кадры WebSocket в аудите: запись на кадр (phase=frame) и запись на сессию
-- (phase=session) при закрытии соединения.
--
-- Соединение -- один запрос: рукопожатие, кадры и сессия лежат под одним
-- ray. Кадр внутри него адресуется стороной и номером, и обе колонки входят
-- в ключ сортировки: ReplacingMergeTree схлопывает по нему, и без них все
-- кадры соединения сложились бы в одну запись. У записей запроса, ответа и
-- сессии сторона пуста и номер ноль -- их ключ не меняется.
--
-- MODIFY ORDER BY принимает только колонки, добавленные тем же ALTER (без
-- умолчания): поэтому одно выражение, а не два. Первичный ключ остаётся
-- прежним префиксом (node, ray, phase). Таблица находок -- следующим файлом:
-- логгер исполняет файл одним запросом, двух ALTER в одном файле нельзя.
--
-- Срез полезной нагрузки -- как body_preview: только в карточке. Сессия
-- несёт счётчики обеих сторон и как закрылась.

ALTER TABLE waf.audit
    ADD COLUMN IF NOT EXISTS frame_direction LowCardinality(String),
    ADD COLUMN IF NOT EXISTS frame_seq UInt64,
    ADD COLUMN IF NOT EXISTS frame_opcode LowCardinality(String),
    ADD COLUMN IF NOT EXISTS frame_size UInt32,
    ADD COLUMN IF NOT EXISTS frame_fin UInt8,
    ADD COLUMN IF NOT EXISTS frame_rewritten UInt8,
    ADD COLUMN IF NOT EXISTS frame_preview String,
    ADD COLUMN IF NOT EXISTS frame_preview_truncated UInt8,
    ADD COLUMN IF NOT EXISTS session_frames_c2s UInt64,
    ADD COLUMN IF NOT EXISTS session_frames_s2c UInt64,
    ADD COLUMN IF NOT EXISTS session_bytes_c2s UInt64,
    ADD COLUMN IF NOT EXISTS session_bytes_s2c UInt64,
    ADD COLUMN IF NOT EXISTS session_denied UInt32,
    ADD COLUMN IF NOT EXISTS session_rewritten UInt32,
    ADD COLUMN IF NOT EXISTS session_close_code UInt16,
    ADD COLUMN IF NOT EXISTS session_close_reason LowCardinality(String),
    ADD COLUMN IF NOT EXISTS session_duration_ms UInt32,
    MODIFY ORDER BY (node, ray, phase, frame_direction, frame_seq);
