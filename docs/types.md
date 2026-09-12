# Типы сообщений

Два контура. На шине — мелкие фрагменты, как их уже пишут агент и инспекторы.
В ClickHouse — одна запись на `(node, ray, phase)`. Нового `kind` на
`WAF_AUDIT` логгер не публикует.

Незнакомое поле — пропуск. Незнакомый `kind` — в сырьё, в склейку не идёт.
`v` пока только `1`.

## Конверт фрагмента

Общие поля любого сообщения в `waf.audit.>`:

| Поле | Тип | Обязательно |
| --- | --- | --- |
| `v` | int | да |
| `kind` | `request` \| `inspector` | да |
| `ts` | RFC3339 milli | да |
| `ray` | UUID v4 | да |
| `node` | string | да |
| `phase` | `request` \| `response` \| `frame` | да |

Ключ склейки — `(node, ray, phase)`. `ray` сквозной: один и тот же в волне, в
`kind=inspector` и в записи лога. `rid` ключом быть не может — это слот
воркера, он повторяется на каждой ноде и переиспользуется после освобождения;
в сокет агента модуль его не кладёт вовсе. Две фазы одного HTTP-запроса — две
записи, поэтому `phase` в ключе.

## `kind=request` — якорь

Пишет модуль в `waf_agent_socket`; агент дописывает `v` и `kind` и публикует на
`waf.audit.request.<node>` **как есть**. Форма —
`messages/agent.schema.ts`, разбор —
`messages/module-agent.md`.

Это единственное сообщение, из которого известно, что за запрос был:
`kind=inspector` описывает только самого инспектора.

```json
{
  "v": 1,
  "kind": "request",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "edge-01",
  "phase": "request",
  "ts": "2026-08-15T21:42:31.660Z",
  "client_ip": "203.0.113.77",
  "client_port": 54233,
  "server_ip": "10.0.0.8",
  "server_port": 443,
  "tls": { "version": "TLSv1.3", "sni": "shop.example.com" },
  "http": {
    "method": "POST", "scheme": "https", "host": "shop.example.com",
    "uri": "/api/orders", "version": "HTTP/1.1",
    "args_size": 37, "headers_size": 962, "headers_count": 11,
    "body_size": 812, "content_type": "application/json", "status": 403
  },
  "route": { "server_name": "shop.example.com", "location": "/api/" },
  "verdict": "deny",
  "code": "score",
  "by": "module",
  "score": { "total": 80, "deny_at": 50, "shadow": 40 },
  "inspectors": {
    "module": { "verdict": "deny" },
    "modsec": { "verdict": "score", "score": 50, "latency_ms": 4, "profile": "strict" },
    "ml": { "state": "timeout", "latency_ms": 20, "role": "passive" }
  },
  "vars": { "ua": "curl/8.5.0", "country": "NL" },
  "store": {
    "headers": { "store": "hot", "driver": "redis", "key": "waf:h:...", "size": 962 },
    "args": null,
    "body": { "store": "hot", "driver": "redis", "key": "waf:b:...", "size": 812 }
  },
  "waf_latency_us": 9100
}
```

Три вопроса — три поля: что сделали (`verdict`), почему (`code`, нет ровно на
`allow`), кто (`by` — ключ в `inspectors`). Итог модуля лежит в той же карте
под ключом `module`, поэтому `verdict === inspectors[by].verdict` — всегда.

Карта `inspectors` раскладывается по колонкам-картам: `inspectors_verdict`,
`inspectors_state`, `inspectors_score`,
`inspectors_latency_ms`, `inspectors_role`, `inspectors_profile`. Фильтруют и
агрегируют по отдельному полю («кто отвечал дольше 20 мс»), а не по записи
целиком. Массив `inspectors` остаётся рядом — `has(inspectors, 'modsec')`
дешевле `mapKeys`; в нём только инспекторы, ключ `module` в него не идёт.

У участника ровно одно из `verdict` / `state`: он либо ответил, либо нет.
Молчун обязан доехать — иначе `code: "fail_timeout"` не объясняет, из-за кого.

Локаторы `store` хранятся строками JSON: их форму задаёт драйвер хранилища, она
меняется вместе с ним, а фильтровать по ним никто не будет — по ключу достают
тело, когда запись уже нашли.

Дубль якоря (at-least-once): ReplacingMergeTree по `(node, ray, phase)`
оставляет последнюю строку. Массив `inspectors` при разборе сортируется — иначе
две доставки одного события дали бы две разные строки, и дедуп бы их не свёл.

## `kind=inspector` — деталь

Пишет инспектор на `waf.audit.inspector.<name>` **после** ответа в inbox.
Вердикт волны это сообщение не двигает.

```json
{
  "v": 1,
  "kind": "inspector",
  "ts": "2026-08-14T11:00:00.120Z",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "edge-01",
  "phase": "request",
  "inspector": "modsec",
  "profile": "default",
  "verdict": "score",
  "score": 50,
  "engine_ms": 1.2,
  "findings": [
    {
      "code": "crs-913100",
      "severity": "critical",
      "target": "header:user-agent",
      "rule": "913100",
      "evidence": "sqlmap/1.7"
    }
  ],
  "engine": {
    "crs_anomaly_score": 5,
    "crs_threshold": 5,
    "crs_would_block": true
  }
}
```

Форма находки одна на всех инспекторов —
`messages/inspector-audit.schema.ts`: правило
CRS у `modsec` и класс уязвимости у `vlai` ложатся в одни и те же
`{code, severity, target, rule}`. Логгер раскладывает `findings[]` построчно в
`waf.audit_finding`, по строке на находку; своё движка едет в `engine` строкой
JSON. См. [tables.md](tables.md).

Инспектор без находок тоже пишет событие, и логгер всё равно даёт строку с
пустым `code`: иначе «не вызвали» и «вызвали, чисто» не различить. Дубль того же
`inspector` в ключе — последний выигрывает.

## Запись лога — продукт склейки

Не едет по `WAF_AUDIT`. Позвоночник — `waf.audit`. Находки инспекторов —
в `waf.audit_finding`, не в этой строке.

Колонки — [tables.md](tables.md). Форма строки повторяет якорь: карта
`inspectors` разложена по колонкам-картам, `by` назван `verdict_by` (`BY` —
ключевое слово SQL), локаторы `store` лежат в `store_headers` / `store_args` /
`store_body`.

| Поле | Откуда |
| --- | --- |
| весь контекст запроса, `verdict`, `code`, `verdict_by`, `score`, `deny_at`, `shadow`, карты участников, `vars`, локаторы, `waf_latency_us` | якорь, один в один |
| `ts` | `ts` якоря — момент поступления запроса; своё время логгер ставит только когда чужого нет |
| детали срабатывания правил | таблица инспектора, склейка по `(node, ray)` |

Кого звали и кто промолчал, видно из самого якоря: `inspectors` — список
званых, `inspectors_state` — почему участник не ответил. Отдельные
`inspectors_expected` / `inspectors_missing` не нужны, и `completeness` на
позвоночнике тоже: якорь приходит собранным, а не по кусочкам.

## Что не тип аудита

| Сообщение | Куда |
| --- | --- |
| Вердикт в inbox волны | горячий путь, не лог |
| Пульс `WAF_STATUS` | флот; логгер сам пишет `WAF_STATUS.service.logger.<id>` |
| Кадры (`phase=frame`) | позже, отдельная запись на `conn_id` |
| Тело запроса | указатель в факте; байты — S3/`waf_archive request`, не логгер |

Резерв `kind` на будущее: `frame`. В склейку HTTP-запроса не смешивать.
