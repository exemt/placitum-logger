# Установка

Документ отвечает на четыре вопроса: что должно быть рядом, какими переменными это называется,
как запустить и как убедиться, что записи доезжают.

Логгер — часть контура Placitum, и обычно его ставит фундамент установки (`placitum-core`) вместе
со всем остальным. Здесь — как поставить его отдельно: в свой контур, в чужой кластер или рядом
с уже поднятыми NATS и ClickHouse.

## Что нужно рядом

| Компонент | Обязателен | Зачем |
| --- | --- | --- |
| NATS с JetStream | да | потоки `WAF_AUDIT` и `WAF_LOG`, из них он и читает |
| ClickHouse | да | куда пишет; схему накатывает сам |
| PostgreSQL | нет | только словари страны и ASN: их читает **сам ClickHouse**, логгер лишь подставляет адрес в текст миграции |
| S3-совместимое хранилище | нет | только для `waf-search`: заголовки, строка запроса и тело в карточке инцидента лежат в архиве, а не в ClickHouse |

Требования к железу скромные: процесс упирается во вставку, а не в счёт. Две реплики на контур
до десяти тысяч запросов в секунду — обычная раскладка; памяти каждой хватает гигабайта.

## Потоки JetStream

**Логгер потоки не создаёт.** Он к ним подключается (`BindStream`), и если `WAF_AUDIT` нет,
старт завершается отказом с внятной строкой. Это осознанно: поток — свойство контура, а не
потребителя; создавать его на ходу означало бы молча получить поток с чужими лимитами.

В установке Placitum их заводит фундамент. Руками:

```sh
nats stream add WAF_AUDIT \
  --subjects 'waf.audit.>' --storage file --retention limits \
  --max-age 24h --max-bytes 256MB --discard old --dupe-window 2m --defaults

nats stream add WAF_LOG \
  --subjects 'waf.log.>' --storage file --retention limits \
  --max-age 24h --max-bytes 128MB --discard old --dupe-window 2m --defaults
```

Сутки и четверть гигабайта — буфер на время, пока логгер не читает: при `discard old` переполнение
теряет старые события, а не останавливает писателей. Потока `WAF_LOG` может не быть вовсе — тогда
подписка на журнал ждёт, а аудит работает.

## Переменные

### `waf-logger`

| Переменная | По умолчанию | Что |
| --- | --- | --- |
| `WAF_NATS_URL` | `nats://127.0.0.1:4222` | шина: потоки аудита и журнала, кадр присутствия |
| `CLICKHOUSE_ADDR` | `127.0.0.1:9000` | нативный порт ClickHouse (не HTTP) |
| `CLICKHOUSE_USER` | `waf` | учётная запись ClickHouse |
| `CLICKHOUSE_PASSWORD` | `waf` | её пароль |
| `WAF_SCHEMA_DIR` | `/app/schema` в образе | каталог миграций |
| `WAF_LOGGER_LOG` | `info` | стартовый уровень журнала: `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert` |
| `WAF_SERVICE_NAME` | `logger` | имя в кадре присутствия |
| `WAF_HEARTBEAT_EVERY` | `4s` | период кадра `WAF_STATUS.service.logger.<id>` |
| `WAF_LOG_SHIP` | `on` | уезжает ли собственный журнал процесса на шину; `off` оставляет только stdout |
| `WAF_LOG_WRITER` | имя машины | чем подписан журнал процесса в `waf.log` |
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | `postgres`, `5432`, `waf`, `waf`, `waf` | подстановки в миграции словарей гео: адрес, по которому **ClickHouse** ходит за каталогом |

### `waf-search`

| Переменная | По умолчанию | Что |
| --- | --- | --- |
| `SEARCH_PORT` | `8091` | порт HTTP API |
| `CLICKHOUSE_ADDR`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | как выше | откуда читает |
| `WAF_SEARCH_LOG` | `info` | уровень журнала |
| `WAF_NATS_URL` | пусто | только ради собственного журнала и живого уровня; без него поиск работает |
| `WAF_STORE_S3_ENDPOINT` | пусто | архив: адрес хранилища. Пусто — карточка честно скажет, что содержимого не будет |
| `WAF_STORE_S3_REGION` | `us-east-1` | регион |
| `WAF_STORE_S3_CREDENTIALS_FILE` | пусто | файл реквизитов в формате AWS-профиля (`aws_access_key_id`, `aws_secret_access_key`) |
| `WAF_STORE_S3_ACCESS_KEY`, `WAF_STORE_S3_SECRET_KEY` | пусто | то же переменными, если файла нет |
| `WAF_STORE_BUCKET_HEADERS`, `WAF_STORE_BUCKET_ARGS`, `WAF_STORE_BUCKET_BODY` | пусто | три бакета архива; имена те же, что у агента ноды |
| `WAF_STORE_MAX_BYTES` | `256k` | потолок объекта, который карточка покажет целиком |
| `WAF_STORE_OP_TIMEOUT` | `5s` | таймаут похода в архив |

Архив настроен криво — отказ на старте, а не сюрприз в момент разбора инцидента.

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
    ports: ["8091:8091"]
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

`:8091` наружу не выставляют: в поиск ходит панель, а не браузер.

## Kubernetes

Deployment на два-три пода для логгера и один для поиска; Service нужен только поиску.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: placitum-logger
spec:
  replicas: 2
  selector:
    matchLabels: { app: placitum-logger }
  template:
    metadata:
      labels: { app: placitum-logger }
    spec:
      containers:
        - name: logger
          image: placitum/logger:<версия>
          env:
            - { name: WAF_NATS_URL,       value: "nats://waf-nats:4222" }
            - { name: CLICKHOUSE_ADDR,    value: "waf-clickhouse:9000" }
            - { name: CLICKHOUSE_USER,    value: "waf" }
            - name: CLICKHOUSE_PASSWORD
              valueFrom: { secretKeyRef: { name: waf-clickhouse, key: password } }
          resources:
            requests: { cpu: "500m", memory: 512Mi }
            limits:   { cpu: "2",    memory: 1Gi }
```

Миграции накатывает сам под при старте, и две реплики за них не подерутся: на время прохода
берётся блокировка. Отдельная Job не нужна.

## Проверка после запуска

```sh
# 1. Миграции применились
clickhouse-client -q "SELECT count() FROM waf.schema_migrations"

# 2. Consumer подключился и читает
nats consumer info WAF_AUDIT logger-audit-v2

# 3. Записи доезжают (после любого трафика через контур)
clickhouse-client -q "SELECT count() FROM waf.audit WHERE ts > now() - INTERVAL 5 MINUTE"

# 4. Поиск отвечает
curl -fsS http://127.0.0.1:8091/healthz
```

В журнале процесса при здоровом старте: `migrations applied`, затем `consuming` с именем потока
и durable.

## Обновление

Обновление образа и есть обновление схемы: новые миграции накатятся при старте, отметки лягут в
`waf.schema_migrations`. Откат образа назад **не откатывает схему** — миграции идут только вперёд,
и это осознанно: обратная миграция на живых данных теряет их молча.

## Грабли

- **`CLICKHOUSE_DB` не читается.** Имя базы `waf` зашито в миграции и запросы; переменная, если
  вы её видели в чужих примерах, ничего не делает.
- **Словари гео без Postgres.** Миграции создадут словари страны и ASN, но без доступной базы
  каталога они не загрузятся. Ломаются только фильтры по стране и ASN — остальной поиск работает.
- **Переименованный durable.** Consumer называется `logger-audit-v2`: у JetStream нельзя поменять
  фильтр существующему consumer'у, и при переходе на чтение всего потока завели новый. Старый
  `logger-audit` после обновления остаётся висеть пустым — снять руками.
- **Поток `WAF_LOG` может отсутствовать.** Подписка на журнал тогда ждёт его появления, а аудит
  читается как обычно; отказ одной половины вторую не роняет.
