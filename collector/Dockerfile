# Базовые образы пришпилены по digest (multi-arch index, одинаков на Docker Hub
# и зеркалах). Обновление digest'а:
#   curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json' \
#     https://mirror.gcr.io/v2/library/golang/manifests/1.26 | grep -i docker-content-digest
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /collector ./cmd/collector

# Distroless без shell и busybox: healthcheck — подкоманда самого бинаря
# (`/collector healthcheck` → GET /healthz, exit 0/1), в compose:
#   healthcheck: { test: ["CMD", "/collector", "healthcheck"] }
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /collector /collector
COPY collector.yml /etc/argus/collector.yml
ENV COLLECTOR_CONFIG=/etc/argus/collector.yml
EXPOSE 5514/udp 5514/tcp 6514/tcp 2055/udp 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/collector", "healthcheck"]
ENTRYPOINT ["/collector"]
