# Placitum logger

English · [Русский](README.ru.md)

Placitum log store: it reads the audit stream from the bus, splits messages into tables and writes
them to ClickHouse in batches. Next to it runs the search over what was written.

It stays off the hot path: a ClickHouse hiccup does not move the deadline of a request check.
JetStream is the buffer, and the logger is a durable consumer.

```
waf.audit.request.<node>     ─┐
waf.audit.inspector.<name>   ─┴─►  waf-logger  ─ batch ─►  waf.audit, waf.audit_finding
                                        │
waf.log.<writer>             ────►      │      ─ batch ─►  waf.log
  (node agents, installation processes) │
                                        └─ JetStream ack after the insert

                                   waf-search  ──►  /api/audit, /api/findings, /api/logs
```

The image holds two binaries. `waf-logger` reads the bus and applies the ClickHouse schema at start;
`waf-search` serves the search HTTP API for the panel on `:8091`. The container command picks one;
the default is the logger.

## What is stored

| Table | One row per | Kept |
| --- | --- | --- |
| `waf.audit` | request phase or WebSocket frame: connection, route, verdict, score, inspector results, previews, archive keys | 90 days |
| `waf.audit_finding` | finding of an inspector: rule, code, severity, evidence, message and tags | 90 days |
| `waf.log` | line of a process or nginx log | 14 days |

Records of one request are joined on read by `node` and `ray`: replicas write independently and never
wait for each other. The `waf.geo_country` and `waf.geo_asn` dictionaries are loaded by ClickHouse
itself from the controller's PostgreSQL and serve the country and AS filters of the search.

## Search API

| Route | What it answers |
| --- | --- |
| `GET /api/audit` | requests by filter |
| `GET /api/audit/groups` | requests grouped for the incident list |
| `GET /api/audit/{node}/{ray}` | one request with its phases |
| `GET /api/audit/{node}/{ray}/inspectors`, `…/findings` | inspector results and findings of a request |
| `GET /api/audit/{node}/{ray}/headers`, `…/args`, `…/body` | archived content from S3 |
| `GET /api/findings` | findings by filter, including `tag` |
| `GET /api/logs`, `GET /api/logs/facets` | log lines and their facets |
| `GET /healthz` | liveness |

The panel calls the search; `:8091` is not meant to be published.

## Schema

`waf-logger` applies `schema/` at start: one statement per file, applied files are recorded in
`waf.schema_migrations`, and a lock keeps replicas that start together from racing. The schema is
created on an empty database; there are no upgrade migrations.

What it needs, the settings and the checks are in [INSTALL.md](INSTALL.md).

## License

[Apache License 2.0](LICENSE); the attribution notice is in [NOTICE](NOTICE). This repository is
part of the Placitum open core. The inspectors are licensed separately: each inspector repository
carries the Placitum License Agreement. Versions up to 1.0.1 were released under the Placitum
License Agreement 1.1.
