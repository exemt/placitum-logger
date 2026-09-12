# placitum/logger

Журнал контура Placitum: читает поток аудита с шины, раскладывает сообщения по таблицам и
батчами кладёт в ClickHouse. Рядом — поиск по тому, что записано.

Сайдкар вне горячего пути: промах ClickHouse не двигает дедлайн проверки запроса. JetStream —
буфер, логгер — durable consumer.

```
waf.audit.request.<нода>     ─┐
waf.audit.inspector.<имя>    ─┴─►  waf-logger  ─ пачкой ─►  waf.audit, waf.audit_finding
                                        │
waf.log.<писатель>           ────►      │      ─ пачкой ─►  waf.log
  (агенты нод, процессы контура)        │
                                        └─ ack JetStream после вставки

                                   waf-search  ──►  /api/audit, /api/findings, /api/logs
```

**Один образ — два бинаря.** `waf-logger` читает шину и накатывает схему ClickHouse при старте;
`waf-search` отдаёт HTTP API поиска для панели (`:8091`). Что запускать, решает команда
контейнера: по умолчанию — логгер.

## Сборка и запуск

```sh
docker build -t placitum/logger .
docker run --rm -e WAF_NATS_URL=nats://nats:4222 -e CLICKHOUSE_ADDR=clickhouse:9000 placitum/logger
docker run --rm -p 8091:8091 -e CLICKHOUSE_ADDR=clickhouse:9000 placitum/logger waf-search
```

Образ собирается и прямо из git, без клона:

```sh
docker buildx build -t placitum/logger "https://github.com/exemt/placitum-logger.git#develop"
```

Что должно быть рядом, все переменные, потоки JetStream и проверка после запуска —
[INSTALL.md](INSTALL.md).

## Что нужно знать до установки

- **Потоки JetStream логгер не создаёт.** Он к ним подключается; без `WAF_AUDIT` не стартует
  вовсе. Заводит их фундамент установки (`placitum-core`), руками — двумя командами из
  [INSTALL.md](INSTALL.md#потоки-jetstream).
- **Схему ClickHouse накатывает он сам** — 35 миграций из `schema/`, отметки в
  `waf.schema_migrations`, блокировка против гонки реплик. Обновление схемы = обновление образа.
- **Реплик может быть сколько угодно.** Durable consumer один на всех, события друг друга не
  ждут: у каждого свой `ray`, связывают по нему на чтении.

## Документация

| Документ | О чём |
| --- | --- |
| [INSTALL.md](INSTALL.md) | что нужно рядом, переменные, потоки, compose и Kubernetes, проверка |
| [docs/tables.md](docs/tables.md) | таблицы ClickHouse: `waf.audit`, `waf.audit_finding`, `waf.log`, словари |
| [docs/types.md](docs/types.md) | типы сообщений на шине: якорь, находки, запись журнала |
| [docs/search.md](docs/search.md) | поиск и агрегация: что ищут, что считают, ручки, индексы |
| [docs/design.md](docs/design.md) | устройство: два потребителя, почему не движок NATS, что не его |

## Ветки

`develop` — то, что разрабатывается: сюда приезжает каждая выкладка. `main` — выкаченные сборки:
наполняется в момент релиза и тегируется.

Правок в этом репозитории не делают: обе ветки производные от платформы, и правка потеряется на
следующей выкладке.

## Лицензия

[Placitum License](LICENSE.md).
