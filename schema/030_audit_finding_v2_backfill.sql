-- Перелив находок: как 026 у позвоночника -- колонки с обеих сторон,
-- повторный запуск схлопывается дедупом.

INSERT INTO waf.audit_finding
    (ts, node, ray, phase, rev,
     inspector, profile, verdict, score, engine_ms,
     finding_idx, code, severity, target, rule,
     offset, length, confidence, evidence, engine,
     frame_direction, frame_seq)
SELECT
     ts, node, ray, phase, rev,
     inspector, profile, verdict, score, engine_ms,
     finding_idx, code, severity, target, rule,
     offset, length, confidence, evidence, engine,
     frame_direction, frame_seq
FROM waf.audit_finding_v1
