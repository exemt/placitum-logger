# Контекст сборки -- корень репозитория. Отсюда же образ собирается прямо из
# git, без клона: контекстом docker принимает URL с веткой или тегом.
#
#     docker build -t placitum/logger .
#     docker buildx build -t placitum/logger:0.1.0 \
#         --build-arg VERSION=0.1.0 --build-arg REVISION=$(git rev-parse --short HEAD) \
#         "https://github.com/exemt/placitum-logger.git#develop"
#
# Один образ -- два бинаря: waf-logger (поток аудита и журнала в ClickHouse,
# он же накатывает схему) и waf-search (HTTP API поиска для панели). Что из
# них запускать, решает команда контейнера.

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре сюда подставляют своё
# зеркало. Выключать GOSUMDB нельзя -- это сверка контрольных сумм модулей.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

# Зависимости отдельным слоем: они меняются на порядок реже кода. download, а
# не tidy: сборка обязана повторять go.mod, а не переписывать его.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY schema ./schema

# Тесты в сборке: образ, собранный с красными тестами, всё равно нельзя
# ставить. Сквозная проверка на живом ClickHouse пропускается сама -- она
# просыпается только при WAF_CH_ADDR в окружении.
RUN go test ./...

# Сборка в бинарь: версия и ревизия видны в журнале старта и в кадре
# присутствия, а не только в метках образа.
ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/waf-logger ./cmd/logger && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/waf-search ./cmd/search

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает, и сам
# себя образ подписать не может.
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/logger" \
      org.opencontainers.image.description="Placitum logger and search: audit stream to ClickHouse, incident search API" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-logger" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/waf-logger /out/waf-search /usr/local/bin/
# Схема ClickHouse едет в образе: её накатывает сам логгер при старте.
COPY schema /app/schema

RUN adduser -D -H -u 10003 waflogger
USER waflogger

ENV WAF_NATS_URL=nats://nats:4222 \
    CLICKHOUSE_ADDR=clickhouse:9000 \
    WAF_SCHEMA_DIR=/app/schema \
    WAF_LOGGER_LOG=info \
    WAF_SEARCH_LOG=info

# HEALTHCHECK в образе не объявлен намеренно: у двух его бинарей разные
# признаки здоровья. У waf-search это GET /healthz на :8091 -- его ставит
# установка на своём сервисе; у waf-logger HTTP нет вовсе, его состояние
# видно в кадре пульса на шине.
EXPOSE 8091

CMD ["waf-logger"]
