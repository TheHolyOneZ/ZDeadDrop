FROM rust:1-slim AS build
WORKDIR /src

COPY . .
RUN cargo build --release -p zdd-relay

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/zdd-relay /usr/local/bin/zdd-relay

USER 65532:65532
VOLUME ["/var/lib/zdd-relay"]
ENV ZDD_RELAY_DATA=/var/lib/zdd-relay \
    ZDD_RELAY_BIND=0.0.0.0:8787
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/zdd-relay"]
