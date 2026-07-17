FROM rust:1.93-bookworm AS builder

WORKDIR /usr/src/anchor
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin anchor \
    && install --directory --owner anchor --group anchor /etc/anchor

COPY --from=builder /usr/src/anchor/target/release/anchor /usr/local/bin/anchor

USER anchor
EXPOSE 2115
ENTRYPOINT ["anchor"]
CMD ["serve"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["anchor", "health", "--url", "http://127.0.0.1:2115/health"]
