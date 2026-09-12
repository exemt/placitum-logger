-- Старые строки переезжают в новую таблицу. Колонки перечислены с обеих
-- сторон, а не `SELECT *`: та маппит по позиции, и таблица, у которой
-- колонки когда-то добавляли вручную не в том порядке, переехала бы с
-- перепутанными полями молча.
--
-- Повторный запуск безопасен: ключ склейки тот же, ReplacingMergeTree
-- схлопнет второй экземпляр строки при слиянии. Поэтому сорванный посреди
-- перелив (рестарт логгера, таймаут) просто идёт заново.
--
-- Строки, записанные после подмены 025, лежат уже в новой таблице и сюда не
-- попадают: waf.audit_v3 с момента переименования никто не пишет.
--
-- Порядок чтения источника -- его старый ключ, то есть по времени вразнобой;
-- вставка сортирует каждый блок под новый ключ сама, и куски, которые от
-- этого пересекаются по времени, сольёт фоновое слияние партиции. Стенд с
-- двумя миллионами строк на двух ядрах переливается за минуту с небольшим.

INSERT INTO waf.audit
    (ts, node, ray, phase, rev,
     client_ip, client_port, server_ip, server_port, tls_version, tls_sni,
     method, scheme, host, uri, http_version,
     args_size, headers_size, headers_count, body_size, content_type,
     status, upstream_status,
     server_name, location, location_id,
     verdict, code, verdict_by,
     score, deny_at, shadow, waf_latency_us,
     inspectors, inspectors_verdict, inspectors_state, inspectors_score,
     inspectors_latency_ms, inspectors_role, inspectors_profile,
     vars,
     store_headers, store_args, store_body,
     headers_preview, args_preview, body_preview,
     headers_preview_truncated, args_preview_truncated,
     headers_preview_dropped, args_preview_dropped,
     actions, rewrite,
     frame_direction, frame_seq, frame_opcode, frame_size, frame_fin,
     frame_rewritten, frame_preview, frame_preview_truncated,
     session_frames_c2s, session_frames_s2c, session_bytes_c2s,
     session_bytes_s2c, session_denied, session_rewritten,
     session_close_code, session_close_reason, session_duration_ms,
     sessions_by, sessions_source, sessions_kind, sessions_user, sessions_id,
     sessions_verified, sessions_issued, sessions_expires, sessions_groups,
     sessions_passive,
     markers)
SELECT
     ts, node, ray, phase, rev,
     client_ip, client_port, server_ip, server_port, tls_version, tls_sni,
     method, scheme, host, uri, http_version,
     args_size, headers_size, headers_count, body_size, content_type,
     status, upstream_status,
     server_name, location, location_id,
     verdict, code, verdict_by,
     score, deny_at, shadow, waf_latency_us,
     inspectors, inspectors_verdict, inspectors_state, inspectors_score,
     inspectors_latency_ms, inspectors_role, inspectors_profile,
     vars,
     store_headers, store_args, store_body,
     headers_preview, args_preview, body_preview,
     headers_preview_truncated, args_preview_truncated,
     headers_preview_dropped, args_preview_dropped,
     actions, rewrite,
     frame_direction, frame_seq, frame_opcode, frame_size, frame_fin,
     frame_rewritten, frame_preview, frame_preview_truncated,
     session_frames_c2s, session_frames_s2c, session_bytes_c2s,
     session_bytes_s2c, session_denied, session_rewritten,
     session_close_code, session_close_reason, session_duration_ms,
     sessions_by, sessions_source, sessions_kind, sessions_user, sessions_id,
     sessions_verified, sessions_issued, sessions_expires, sessions_groups,
     sessions_passive,
     markers
FROM waf.audit_v3
