# Базовые образы пришпилены по digest (см. collector/Dockerfile — как обновлять).
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src
# Общий модуль редакции и фильтров (replace ../triage в go.mod) — именованный
# контекст triage: compose (build.additional_contexts), release.yml (build-contexts),
# вручную: docker build --build-context triage=./triage ./<сервис>.
COPY --from=triage . /triage
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG APP_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${APP_VERSION}" -o /argus-mcp .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /argus-mcp /argus-mcp
EXPOSE 8095
ENTRYPOINT ["/argus-mcp"]
