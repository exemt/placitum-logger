-- Подмена находок: как 025 у позвоночника. RENAME парой, а не EXCHANGE --
-- второй запуск падает, а не откатывает молча.

RENAME TABLE waf.audit_finding TO waf.audit_finding_v1, waf.audit_finding_v2 TO waf.audit_finding
