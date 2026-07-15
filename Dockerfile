FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
WORKDIR /src
COPY . .
ARG PROJECT_VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
ARG MOSDNS_BASE=v5.3.4
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.projectVersion=${PROJECT_VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.mosdnsBase=${MOSDNS_BASE} -X main.buildTime=${BUILD_TIME} -X github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_rule_engine.Version=${PROJECT_VERSION} -X github.com/IrineSistiana/mosdns/v5/plugin/executable/query_audit.Version=${PROJECT_VERSION}" -o /out/mosdns ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/dns-healthcheck ./cmd/dns-healthcheck

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -S mosdns && adduser -S -G mosdns -u 10001 mosdns && mkdir -p /var/lib/mosdns && chown -R mosdns:mosdns /var/lib/mosdns
COPY --from=builder /out/mosdns /usr/local/bin/mosdns
COPY --from=builder /out/dns-healthcheck /usr/local/bin/dns-healthcheck
USER mosdns
ENTRYPOINT ["/usr/local/bin/mosdns"]
