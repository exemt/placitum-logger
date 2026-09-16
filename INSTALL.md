# Installation

English · [Русский](INSTALL.ru.md)

The logger is part of Placitum, and `placitum-core` usually installs it with everything else. This
document is for installing it separately, next to NATS and ClickHouse that are already running.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS with JetStream | yes | the `WAF_AUDIT` and `WAF_LOG` streams it reads |
| ClickHouse | yes | where it writes; it applies the schema itself |
| PostgreSQL | no | only the country and AS dictionaries: **ClickHouse** reads them, the logger only puts the address into the schema |
| S3-compatible storage | no | only for `waf-search`: headers, query string and body of an incident live in the archive, not in ClickHouse |

The load is modest: the process is bound by inserts, not by computation. Two replicas for up to ten
thousand requests per second is a usual layout, with a gigabyte of memory each.

## JetStream streams

**The logger does not create streams.** It binds to them, and without `WAF_AUDIT` the start fails
with a clear message: a stream belongs to the installation, and creating one on the fly would quietly
give it someone else's limits. `placitum-core` creates them; by hand:

```sh
nats stream add WAF_AUDIT \
  --subjects 'waf.audit.>' --storage file --retention limits \
  --max-age 24h --max-bytes 256MB --discard old --dupe-window 2m --defaults

nats stream add WAF_LOG \
  --subjects 'waf.log.>' --storage file --retention limits \
  --max-age 24h --max-bytes 128MB --discard old --dupe-window 2m --defaults
```

A day and a quarter of a gigabyte is the buffer for the time the logger is not reading: with
`discard old` an overflow loses old events instead of stopping the writers. `WAF_LOG` may be absent:
the log subscription then waits for it, and the audit is read as usual.

## Settings

### waf-logger

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAF_NATS_URL` | `nats://127.0.0.1:4222` | bus: audit and log streams, presence frame |
| `CLICKHOUSE_ADDR` | `127.0.0.1:9000` | ClickHouse native port (not HTTP) |
| `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | `waf`, `waf` | ClickHouse account |
| `WAF_SCHEMA_DIR` | `schema`; `/app/schema` in the image | schema directory |
| `WAF_LOGGER_LOG` | `info` | starting log level: `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert` |
| `WAF_SERVICE_NAME` | `logger` | name in the presence frame |
| `WAF_HEARTBEAT_EVERY` | `4s` | interval of the `WAF_STATUS.service.logger.<id>` frame |
| `WAF_LOG_SHIP` | `on` | whether the process log goes to the bus; `off` keeps it on stdout only |
| `WAF_LOG_WRITER` | host name | writer name of the process log in `waf.log` |
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | `postgres`, `5432`, `waf`, `waf`, `waf` | put into the dictionary definitions: where **ClickHouse** reads the catalogue |

### waf-search

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEARCH_PORT` | `8091` | HTTP API port |
| `CLICKHOUSE_ADDR`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | as above | where it reads |
| `WAF_SEARCH_LOG` | `info` | log level |
| `WAF_NATS_URL` | empty | only for its own log and live log level; search works without it |
| `WAF_STORE_S3_ENDPOINT` | empty | archive address; empty means the incident card says there is no content |
| `WAF_STORE_S3_REGION` | `us-east-1` | region |
| `WAF_STORE_S3_CREDENTIALS_FILE` | empty | credentials file in AWS profile format (`aws_access_key_id`, `aws_secret_access_key`) |
| `WAF_STORE_S3_ACCESS_KEY`, `WAF_STORE_S3_SECRET_KEY` | empty | the same as variables, when there is no file |
| `WAF_STORE_BUCKET_HEADERS`, `WAF_STORE_BUCKET_ARGS`, `WAF_STORE_BUCKET_BODY` | empty | the three archive buckets, the same names as on the node agent |
| `WAF_STORE_MAX_BYTES` | `256k` | largest object the card shows whole |
| `WAF_STORE_OP_TIMEOUT` | `5s` | archive request timeout |

A broken archive configuration fails the start instead of surprising you during an incident.

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

## Checking

```sh
# 1. The schema is applied: five files
clickhouse-client -q "SELECT count() FROM waf.schema_migrations"

# 2. The consumer is attached and reading
nats consumer info WAF_AUDIT logger-audit-v2

# 3. Records arrive (after any traffic through a node)
clickhouse-client -q "SELECT count() FROM waf.audit WHERE ts > now() - INTERVAL 5 MINUTE"

# 4. Search answers
curl -fsS http://127.0.0.1:8091/healthz
```

A healthy start logs `migrations applied`, then `consuming` with the stream and the durable name.

## Pitfalls

- **`CLICKHOUSE_DB` is not read.** The database name `waf` is fixed in the schema and the queries.
- **Geo dictionaries without PostgreSQL.** The dictionaries are created, but without the catalogue
  they do not load; only the country and AS filters break, the rest of the search works.
- **Replicas starting together** wait for one another on the schema lock; this is normal and short.
