# Базовые образы пришпилены по digest (см. collector/Dockerfile — как обновлять).
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /policyd ./cmd/policyd

# Статический busybox — только ради healthcheck (wget --spider) в distroless.
FROM ${REGISTRY}/library/busybox:1.37-musl@sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23 AS busybox

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=busybox /bin/busybox /bin/busybox
COPY --from=build /policyd /policyd
EXPOSE 8080
ENTRYPOINT ["/policyd"]
