# Установка

[English](INSTALL.md) · Русский

Логгер — часть Placitum, и обычно его ставит `placitum-core` вместе со всем остальным. Этот документ —
для установки отдельно, рядом с уже работающими NATS и ClickHouse.

## Что нужно рядом

| Компонент | Обязателен | Зачем |
| --- | --- | --- |
| NATS с JetStream | да | потоки `WAF_AUDIT` и `WAF_LOG`, из которых он читает |
| ClickHouse | да | куда пишет; схему накатывает сам |
| PostgreSQL | нет | только словари страны и системы: их читает **сам ClickHouse**, логгер лишь подставляет адрес в схему |
| S3-совместимое хранилище | нет | только для `waf-search`: заголовки, строка запроса и тело инцидента лежат в архиве, а не в ClickHouse |

Нагрузка скромная: процесс упирается во вставку, а не в счёт. Две реплики на установку до десяти
тысяч запросов в секунду — обычная раскладка, памяти каждой хватает гигабайта.

## Потоки JetStream

**Логгер потоки не создаёт.** Он к ним подключается, и без `WAF_AUDIT` старт завершается ошибкой с
понятной строкой: поток — свойство установки, и создать его на ходу значило бы молча получить поток с
чужими лимитами. Заводит их `placitum-core`; руками:

```sh
nats stream add WAF_AUDIT \
  --subjects 'waf.audit.>' --storage file --retention limits \
  --max-age 24h --max-bytes 256MB --discard old --dupe-window 2m --defaults

nats stream add WAF_LOG \
  --subjects 'waf.log.>' --storage file --retention limits \
  --max-age 24h --max-bytes 128MB --discard old --dupe-window 2m --defaults
```

Сутки и четверть гигабайта — буфер на время, пока логгер не читает: при `discard old` переполнение
теряет старые события, а не останавливает писателей. `WAF_LOG` может не быть: подписка на журнал тогда
ждёт его появления, а аудит читается как обычно.

## Настройки

### waf-logger

| Переменная | По умолчанию | Что задаёт |
| --- | --- | --- |
| `WAF_NATS_URL` | `nats://127.0.0.1:4222` | шина: потоки аудита и журнала, кадр присутствия |
| `CLICKHOUSE_ADDR` | `127.0.0.1:9000` | нативный порт ClickHouse (не HTTP) |
| `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | `waf`, `waf` | учётная запись ClickHouse |
| `WAF_SCHEMA_DIR` | `schema`; в образе `/app/schema` | каталог схемы |
| `WAF_LOGGER_LOG` | `info` | стартовый уровень журнала: `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert` |
| `WAF_SERVICE_NAME` | `logger` | имя в кадре присутствия |
| `WAF_HEARTBEAT_EVERY` | `4s` | период кадра `WAF_STATUS.service.logger.<id>` |
| `WAF_LOG_SHIP` | `on` | уходит ли журнал процесса на шину; `off` оставляет только stdout |
| `WAF_LOG_WRITER` | имя машины | чем подписан журнал процесса в `waf.log` |
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | `postgres`, `5432`, `waf`, `waf`, `waf` | подставляются в определения словарей: где **ClickHouse** читает каталог |

### waf-search

| Переменная | По умолчанию | Что задаёт |
| --- | --- | --- |
| `SEARCH_PORT` | `8091` | порт HTTP API |
| `SEARCH_HOST` | пусто | адрес, на котором слушать; пусто — все адреса, так и нужно в контейнере. Без Docker ставьте `127.0.0.1`: у API нет входа |
| `CLICKHOUSE_ADDR`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | как выше | откуда читает |
| `WAF_SEARCH_LOG` | `info` | уровень журнала |
| `WAF_NATS_URL` | пусто | только ради собственного журнала и живого уровня; поиск работает и без него |
| `WAF_STORE_S3_ENDPOINT` | пусто | адрес архива; пусто — карточка скажет, что содержимого не будет |
| `WAF_STORE_S3_REGION` | `us-east-1` | регион |
| `WAF_STORE_S3_CREDENTIALS_FILE` | пусто | файл реквизитов в формате AWS-профиля (`aws_access_key_id`, `aws_secret_access_key`) |
| `WAF_STORE_S3_ACCESS_KEY`, `WAF_STORE_S3_SECRET_KEY` | пусто | то же переменными, если файла нет |
| `WAF_STORE_BUCKET_HEADERS`, `WAF_STORE_BUCKET_ARGS`, `WAF_STORE_BUCKET_BODY` | пусто | три бакета архива, те же имена, что у агента узла |
| `WAF_STORE_MAX_BYTES` | `256k` | крупнейший объект, который карточка покажет целиком |
| `WAF_STORE_OP_TIMEOUT` | `5s` | таймаут похода в архив |

Криво настроенный архив роняет старт, а не удивляет в момент разбора инцидента.

## Docker Compose

```yaml
services:
  logger:
    image: placitum/logger
    environment:
      WAF_NATS_URL: nats://nats:4222
      CLICKHOUSE_ADDR: clickhouse:9000
      CLICKHOUSE_USER: waf
      CLICKHOUSE_PASSWORD: waf
    depends_on: [nats, clickhouse]

  search:
    image: placitum/logger
    command: ["waf-search"]
    environment:
      CLICKHOUSE_ADDR: clickhouse:9000
      CLICKHOUSE_USER: waf
      CLICKHOUSE_PASSWORD: waf
      WAF_STORE_S3_ENDPOINT: http://minio:9000
      WAF_STORE_S3_CREDENTIALS_FILE: /run/secrets/waf_s3_creds
      WAF_STORE_BUCKET_HEADERS: waf-headers
      WAF_STORE_BUCKET_ARGS: waf-args
      WAF_STORE_BUCKET_BODY: waf-bodies
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8091/healthz"]
      interval: 10s
      timeout: 3s
      retries: 3
```

## Проверка

```sh
# 1. Схема накатана: пять файлов
clickhouse-client -q "SELECT count() FROM waf.schema_migrations"

# 2. Consumer подключился и читает
nats consumer info WAF_AUDIT logger-audit-v2

# 3. Записи доходят (после любого трафика через узел)
clickhouse-client -q "SELECT count() FROM waf.audit WHERE ts > now() - INTERVAL 5 MINUTE"

# 4. Поиск отвечает
curl -fsS http://127.0.0.1:8091/healthz
```

При здоровом старте в журнале: `migrations applied`, затем `consuming` с именем потока и durable.

## Типичные ошибки

- **`CLICKHOUSE_DB` не читается.** Имя базы `waf` зашито в схему и запросы.
- **Словари гео без PostgreSQL.** Словари создаются, но без каталога не загружаются; ломаются только
  фильтры по стране и системе, остальной поиск работает.
- **Реплики, стартующие разом,** ждут друг друга на замке схемы; это нормально и недолго.
