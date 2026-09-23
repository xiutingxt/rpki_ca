FROM rust:1.89-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

COPY --from=builder /build/target/release/rpki-ca /usr/local/bin/rpki-ca
COPY docker/entrypoint.sh /usr/local/bin/rpki-ca-entrypoint
RUN chmod 0755 /usr/local/bin/rpki-ca-entrypoint

ENV CA_DIR=/var/lib/rpki/ca \
    REPOSITORY_URI=rsync://localhost/rpki/ \
    CA_NAME=development-ca \
    DEVELOPMENT_CA_VALIDITY_DAYS=365 \
    CA_RESOURCES="192.0.2.0/24 2001:db8::/48" \
    API_BIND=0.0.0.0:3000

EXPOSE 3000

VOLUME ["/var/lib/rpki"]
ENTRYPOINT ["/usr/local/bin/rpki-ca-entrypoint"]
CMD ["idle"]
