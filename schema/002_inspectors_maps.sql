-- Вердикт и вклад каждого инспектора с якоря.
-- Массив inspectors остаётся: has(inspectors, 'modsec') дешевле mapKeys.
-- Строку "modsec: score [50]" не храним — её собирает SELECT / UX.

ALTER TABLE waf.audit
    ADD COLUMN IF NOT EXISTS inspectors_verdict Map(LowCardinality(String), LowCardinality(String)),
    ADD COLUMN IF NOT EXISTS inspectors_score   Map(LowCardinality(String), Int32);
