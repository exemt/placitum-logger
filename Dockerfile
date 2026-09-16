FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/waf-logger ./cmd/logger && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/waf-search ./cmd/search

FROM alpine:3.22

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
COPY schema /app/schema

RUN adduser -D -H -u 10003 waflogger
USER waflogger

ENV WAF_NATS_URL=nats://nats:4222 \
    CLICKHOUSE_ADDR=clickhouse:9000 \
    WAF_SCHEMA_DIR=/app/schema \
    WAF_LOGGER_LOG=info \
    WAF_SEARCH_LOG=info

EXPOSE 8091

CMD ["waf-logger"]
