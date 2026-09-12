-- Находки инспекторов на кадре: тот же адрес, тот же ключ. Инспектор кладёт
-- в событие kind=inspector секцию frame {direction, seq}; без неё находки
-- всех кадров соединения легли бы одна на другую.

ALTER TABLE waf.audit_finding
    ADD COLUMN IF NOT EXISTS frame_direction LowCardinality(String),
    ADD COLUMN IF NOT EXISTS frame_seq UInt64,
    MODIFY ORDER BY (node, ray, phase, inspector, finding_idx, frame_direction, frame_seq);
