# Базовые образы пришпилены по digest (см. collector/Dockerfile — как обновлять).
# Контекст сборки — корень репозитория (docker build -f engine/Dockerfile .):
# образ несёт поставляемый набор rules/ и fixtures/events своей версии — реестр
# internal/registry. Корневой .dockerignore пропускает только engine/, rules/ и
# fixtures/events/. Именованные контексты не нужны: classic builder без buildx
# собирает так же.
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src
COPY engine/go.mod engine/go.sum ./
RUN go mod download
COPY engine/ .
RUN CGO_ENABLED=0 go build -trimpath -o /engine ./cmd/engine

# Статический busybox — только ради healthcheck (wget --spider) в distroless.
FROM ${REGISTRY}/library/busybox:1.37-musl@sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23 AS busybox

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=busybox /bin/busybox /bin/busybox
COPY --from=build /engine /engine
COPY engine/argus.analyst.yml /etc/argus/argus.analyst.yml
# Поставляемый набор этой версии (internal/registry). RULES_DIR (/rules) может
# содержать и пользовательские правила — реестр берёт только эту копию, не /rules.
COPY rules/ /usr/share/argus/shipped/rules/
COPY fixtures/events/ /usr/share/argus/shipped/fixtures/
ENV ANALYST_CONFIG=/etc/argus/argus.analyst.yml RULES_DIR=/rules
EXPOSE 8090
ENTRYPOINT ["/engine"]
CMD ["run"]
