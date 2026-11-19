# Базовые образы пришпилены по digest (см. collector/Dockerfile — как обновлять).
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/golang:1.26.11@sha256:4165ee6bf3b7811fd7b40373290405c83d0167dcb87ee5f29c427cdcef45ff8f AS build
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
