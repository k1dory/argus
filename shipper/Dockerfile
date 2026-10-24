# Базовые образы пришпилены по digest (см. collector/Dockerfile — как обновлять).
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/rust:1.89-slim@sha256:8cffb8fe4e8a95cf0d6a2060375e5a28aff4c752155aa9f1f9193530769bdf66 AS build
# Статическая сборка под musl: бинарник без libc и openssl, работает в distroless/static.
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
         amd64) echo x86_64-unknown-linux-musl ;; \
         arm64) echo aarch64-unknown-linux-musl ;; \
         *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
       esac > /rust-target \
    && rustup target add "$(cat /rust-target)"
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --target "$(cat /rust-target)" \
    && cp "target/$(cat /rust-target)/release/wazuh-shipper" /wazuh-shipper

# Статический busybox — только ради healthcheck (wget --spider) в distroless.
FROM ${REGISTRY}/library/busybox:1.37-musl@sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23 AS busybox

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=busybox /bin/busybox /bin/busybox
COPY --from=build /wazuh-shipper /usr/local/bin/wazuh-shipper
# /healthz и /metrics (HEALTH_ADDR): наружу не публикуется — healthcheck ходит
# через busybox внутри контейнера, Prometheus снимает по сети compose.
EXPOSE 9101
ENTRYPOINT ["/usr/local/bin/wazuh-shipper"]
